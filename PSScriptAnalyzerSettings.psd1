# PSScriptAnalyzer settings for this repository.
#
# The excluded rules below are deliberate design decisions, not unreviewed debt:
#
#   PSAvoidUsingWriteHost
#     These scripts are operator-facing console tools. Coloured, ordered progress output
#     IS the interface for the deploy script and the readiness diagnostic. Write-Output
#     would pollute the pipeline; Write-Information is not displayed by default. Write-Host
#     is correct here.
#
#   PSAvoidUsingEmptyCatchBlock
#     The client agent must never fail a drive mapping because a cosmetic side task threw.
#     Log rotation, toast notification, drive labelling and registry cleanup are all
#     best-effort by design, and their catch blocks are intentionally silent. The paths
#     that actually matter (mapping, Kerberos, preflight) all log and set exit codes.
#
#   PSUseShouldProcessForStateChangingFunctions / PSUseSingularNouns
#     Internal helper functions in a script, not exported cmdlets. -WhatIf is handled at
#     the script level in the deploy script, which is where an operator would use it.
#     The client agent is invoked unattended by Task Scheduler and has no -WhatIf story.
#
# Everything else is enforced. PSShouldProcess in particular caught a real bug: a helper
# calling $PSCmdlet.ShouldProcess without declaring SupportsShouldProcess, which only
# worked because it reached the parent scope's $PSCmdlet by dynamic scoping.

@{
    Severity = @('Error', 'Warning')

    ExcludeRules = @(
        'PSAvoidUsingWriteHost',
        'PSAvoidUsingEmptyCatchBlock',
        'PSUseShouldProcessForStateChangingFunctions',
        'PSUseSingularNouns'
    )
}
