using FluentValidation;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Cases;

public sealed class CreateCaseValidator : AbstractValidator<CreateCaseRequest>
{
    public CreateCaseValidator()
    {
        RuleFor(x => x.DescriptiveName)
            .NotEmpty().WithMessage("A short descriptive name is required (used in the case number).")
            .MaximumLength(120);

        RuleFor(x => x.Title).NotEmpty().MaximumLength(300);
        RuleFor(x => x.Summary).MaximumLength(8000);
        RuleFor(x => x.DetectionCaseId).MaximumLength(100);

        When(x => x.Origin == CaseOrigin.ThirdParty, () =>
        {
            RuleFor(x => x.VendorName)
                .NotEmpty().WithMessage("Vendor name is required for a third-party event.")
                .MaximumLength(300);
        });
    }
}
