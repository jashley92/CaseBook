# =============================================================================
#  CaseBook install answers file  (PowerShell data file, *.psd1)
# -----------------------------------------------------------------------------
#  Fill this in ONCE, copy it to both the SQL host and the web host, and pass it
#  to the installers instead of typing a dozen parameters:
#
#       .\Install-Database.ps1 -ConfigFile .\casebook.config.psd1     # on the SQL host (sysadmin)
#       .\Install-CaseBook.ps1 -ConfigFile .\casebook.config.psd1     # on the web host (elevated)
#
#  Prefer to be prompted? Run  .\New-CaseBookConfig.ps1  and it writes this file
#  for you. Any value you also pass on the command line overrides the file.
#
#  SECURITY: this file names AD groups, hosts, and the service account, so treat
#  it as sensitive and do NOT commit the filled-in copy. It holds NO passwords -
#  a gMSA is passwordless, and a normal service account's password is prompted
#  for securely at install time (never stored here).
# =============================================================================
@{
    # --- SQL Server (used by Install-Database.ps1 and Install-CaseBook.ps1) ---
    SqlInstance = 'SQLHOST\PROD'      # instance, e.g. 'SQLHOST' or 'SQLHOST\INSTANCE'
    DbName      = 'CaseBook'          # database name

    # Windows account the IIS app pool runs as AND the SQL login granted to it.
    # gMSA (recommended, passwordless): include the trailing '$', e.g. 'CONTOSO\svc-casebook$'.
    # Normal domain service account: 'CONTOSO\svc-casebook' (you'll be prompted for its
    # password at install time; it is never written to this file).
    AppAccount  = 'CONTOSO\svc-casebook$'

    # 'AppMigrates' (default) - grant the app db_owner so it applies EF migrations on
    #   first start. Simplest; upgrades stay automatic.
    # 'DbaApplies'  - grant only datareader/datawriter/EXECUTE; a DBA runs
    #   sql\casebook-schema-sqlserver.sql. Use where app identities can't hold DDL rights.
    SchemaMode  = 'AppMigrates'

    # Optional explicit locations for the SQL data/log files. Leave '' for instance defaults.
    DataPath    = ''                  # folder for the .mdf, e.g. 'F:\SQLData'
    LogPath     = ''                  # folder for the .ldf, e.g. 'G:\SQLLogs'

    # --- Web host / IIS (used by Install-CaseBook.ps1) ---
    SitePath    = 'D:\inetpub\casebook'   # web root the app publishes to
    DataRoot    = 'E:\CaseBookData'       # evidence/reports/keys/seals/ops - OUTSIDE the web root
    Hostname    = 'casebook.contoso.com'  # public host header

    # Thumbprint of an installed TLS cert in LocalMachine\My for an HTTPS (443) binding.
    # Leave '' to create an HTTP binding for a first smoke test (add TLS before real data).
    CertificateThumbprint = ''

    SiteName    = 'CaseBook'          # IIS site name
    AppPoolName = 'CaseBook'          # IIS app-pool name

    # --- AD security groups mapped to the five application roles (your real group names) ---
    AdGroupAnalysts   = 'SOC-Analysts'
    AdGroupCommanders = 'SOC-IncidentCommanders'
    AdGroupLeadership = 'SOC-Leadership'
    AdGroupLegal      = 'Legal-Privacy'
    AdGroupAppAdmins  = 'SOC-AppAdmins'

    # --- Optional email (stays disabled until turned on in-app under Administration -> Settings) ---
    SmtpHost    = ''                  # e.g. 'smtp.contoso.com'
    MailDomain  = ''                  # e.g. 'contoso.com' (the From address becomes casebook@<domain>)
}
