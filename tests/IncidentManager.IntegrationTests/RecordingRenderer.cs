using System.Runtime.ExceptionServices;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.RenderTree;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.JSInterop;

#pragma warning disable BL0006 // the render tree is read here as the browser would get it

namespace IncidentManager.IntegrationTests;

/// <summary>
/// Renders components as the server would for a browser, and keeps what it would send: each value it writes to a box,
/// and how many components each batch redrew. Keystrokes go in as the browser sends them, by the box's event handler id
/// with the box's text, so Blazor treats them as it does in a real session (a bound box's value follows the typing).
/// Scripts are recorded rather than run.
/// </summary>
internal sealed class RecordingRenderer(IServiceProvider services) : Renderer(services, NullLoggerFactory.Instance)
{
    public sealed class Scripts : IJSRuntime
    {
        public List<string> Calls { get; } = [];

        public ValueTask<TValue> InvokeAsync<TValue>(string identifier, object?[]? args)
        {
            Calls.Add(identifier);
            return ValueTask.FromResult(default(TValue)!);
        }

        public ValueTask<TValue> InvokeAsync<TValue>(string identifier, CancellationToken cancellationToken, object?[]? args) =>
            InvokeAsync<TValue>(identifier, args);
    }

    private sealed class Navigation : NavigationManager
    {
        public Navigation() => Initialize("http://localhost/", "http://localhost/");
        protected override void NavigateToCore(string uri, NavigationOptions options) => Uri = ToAbsoluteUri(uri).ToString();
    }

    /// <summary>A renderer with recorded scripts and a navigation manager at the site's root.</summary>
    public static RecordingRenderer Create() =>
        new(new ServiceCollection().AddSingleton<IJSRuntime, Scripts>().AddSingleton<NavigationManager, Navigation>().BuildServiceProvider());

    public override Dispatcher Dispatcher { get; } = Dispatcher.CreateDefault();

    /// <summary>Each value a render would set on a box in the browser, in order.</summary>
    public List<string?> ValuesSent { get; } = [];

    /// <summary>How many component redraws have been sent.</summary>
    public int Redraws { get; private set; }

    private int _root;

    protected override void HandleException(Exception exception) => ExceptionDispatchInfo.Capture(exception).Throw();

    protected override Task UpdateDisplayAsync(in RenderBatch batch)
    {
        Redraws += batch.UpdatedComponents.Count;
        for (var i = 0; i < batch.UpdatedComponents.Count; i++)
        {
            var diff = batch.UpdatedComponents.Array[i];
            for (var j = 0; j < diff.Edits.Count; j++)
            {
                var edit = diff.Edits.Array[diff.Edits.Offset + j];
                if (edit.Type != RenderTreeEditType.SetAttribute) continue;
                var frame = batch.ReferenceFrames.Array[edit.ReferenceFrameIndex];
                if (frame.AttributeName == "value") ValuesSent.Add(frame.AttributeValue?.ToString());
            }
        }
        return Task.CompletedTask;
    }

    /// <summary>Renders <typeparamref name="T"/> as the page's root, with <paramref name="parameters"/>.</summary>
    public Task<T> Mount<T>(Dictionary<string, object?>? parameters = null) where T : IComponent => Dispatcher.InvokeAsync(async () =>
    {
        var component = (T)InstantiateComponent(typeof(T));
        _root = AssignRootComponentId(component);
        await RenderRootComponentAsync(_root, ParameterView.FromDictionary(parameters ?? []));
        return component;
    });

    /// <summary>The root given new parameters, as a page re-rendering it with them.</summary>
    public Task SetParameters(Dictionary<string, object?> parameters) =>
        Dispatcher.InvokeAsync(() => RenderRootComponentAsync(_root, ParameterView.FromDictionary(parameters)));

    // Every frame drawn now, with the component that drew it.
    private List<(int Component, RenderTreeFrame Frame)> Frames()
    {
        var all = new List<(int, RenderTreeFrame)>();
        void Walk(int id)
        {
            var frames = GetCurrentRenderTreeFrames(id);
            for (var i = 0; i < frames.Count; i++)
            {
                all.Add((id, frames.Array[i]));
                if (frames.Array[i].FrameType == RenderTreeFrameType.Component) Walk(frames.Array[i].ComponentId);
            }
        }
        Walk(_root);
        return all;
    }

    // The page's text box: the first input that handles oninput, and its attributes.
    private (int Component, Dictionary<string, RenderTreeFrame> Attributes) Box()
    {
        var frames = Frames();
        for (var i = 0; i < frames.Count; i++)
        {
            var (component, frame) = frames[i];
            if (frame.FrameType != RenderTreeFrameType.Element || frame.ElementName != "input") continue;
            var attributes = new Dictionary<string, RenderTreeFrame>();
            for (var j = i + 1; j < frames.Count && frames[j].Frame.FrameType == RenderTreeFrameType.Attribute; j++)
                attributes[frames[j].Frame.AttributeName] = frames[j].Frame;
            if (attributes.ContainsKey("oninput")) return (component, attributes);
        }
        throw new InvalidOperationException("No box takes typing.");
    }

    /// <summary>The box's value as the server last drew it.</summary>
    public string? Drawn => Dispatcher.InvokeAsync(() => Box().Attributes.TryGetValue("value", out var v) ? v.AttributeValue?.ToString() : null).Result;

    /// <summary>A keystroke, as the browser sends it: the input event with the box's text. Hands back the handler, which
    /// may still be waiting out a typing pause.</summary>
    public async Task<Task> Type(string text)
    {
        Task handled = Task.CompletedTask;
        await Dispatcher.InvokeAsync(() =>
        {
            var (component, attributes) = Box();
            handled = DispatchEventAsync(attributes["oninput"].AttributeEventHandlerId,
                new EventFieldInfo { ComponentId = component, FieldValue = text }, new ChangeEventArgs { Value = text });
        });
        return handled;
    }

    /// <summary>A key pressed in the box.</summary>
    public async Task Key(string key)
    {
        Task handled = Task.CompletedTask;
        await Dispatcher.InvokeAsync(() =>
            handled = DispatchEventAsync(Box().Attributes["onkeydown"].AttributeEventHandlerId, null, new KeyboardEventArgs { Key = key }));
        await handled;
    }

    /// <summary>Clicks the button that reads <paramref name="label"/>.</summary>
    public async Task Click(string label)
    {
        Task handled = Task.CompletedTask;
        await Dispatcher.InvokeAsync(() =>
        {
            var frames = Frames();
            for (var i = 0; i < frames.Count; i++)
            {
                var frame = frames[i].Frame;
                if (frame.FrameType != RenderTreeFrameType.Element || frame.ElementName != "button") continue;
                var end = i + frame.ElementSubtreeLength;
                if (!frames.Skip(i).Take(end - i).Any(f => f.Frame.FrameType == RenderTreeFrameType.Text && f.Frame.TextContent == label)) continue;
                var click = frames.Skip(i + 1).TakeWhile(f => f.Frame.FrameType == RenderTreeFrameType.Attribute).First(f => f.Frame.AttributeName == "onclick");
                handled = DispatchEventAsync(click.Frame.AttributeEventHandlerId, null, new MouseEventArgs());
                return;
            }
            throw new InvalidOperationException($"No {label} button.");
        });
        await handled;
    }

    /// <summary>Whether anything drawn (text, markup or an attribute's value) contains <paramref name="text"/>.</summary>
    public bool Shows(string text) => Dispatcher.InvokeAsync(() => Frames().Any(f => f.Frame.FrameType switch
    {
        RenderTreeFrameType.Text => f.Frame.TextContent.Contains(text, StringComparison.Ordinal),
        RenderTreeFrameType.Markup => f.Frame.MarkupContent.Contains(text, StringComparison.Ordinal),
        RenderTreeFrameType.Attribute => f.Frame.AttributeValue is string s && s.Contains(text, StringComparison.Ordinal),
        _ => false,
    })).Result;

    /// <summary>Does something on the renderer's thread, as a component's own handler would.</summary>
    public Task Do(Action what) => Dispatcher.InvokeAsync(what);
}
