package repository

import data.common.webhooks as webhookUtils

# METADATA
# scope: rule
# title: Repository Should Have Fewer Than Six Admins
# description: Repository admins are highly privileged and could create great damage if they are compromised. It is recommeneded to limit the number of Repository Admins to the minimum required (recommended maximum 3 admins).
# custom:
#   severity: MEDIUM
#   remediationSteps: [Make sure you have admin permissions, Go to the repository settings page, Press "Collaborators and teams", Select the unwanted admin users, Select "Change Role"]
#   requiredScopes: [read:org,repo]
#   threat:
#     - "A compromised user with admin permissions can initiate a supply chain attack in a plethora of ways."
#     - "Having many admin users increases the overall risk of user compromise, and makes it more likely to lose track of unused admin permissions given to users in the past."
default repository_has_too_many_admins := true

repository_has_too_many_admins := false {
	admins := [admin | admin := input.collaborators[_]; admin.permissions.admin]
	count(admins) <= 14
}

# METADATA
# scope: rule
# title: Webhooks Should Be Configured With A Secret
# description: Webhooks are not configured with a shared secret to validate the origin and content of the request. This could allow your webhook to be triggered by any bad actor with the URL.
# custom:
#   requiredEnrichers: [hooksList]
#   severity: LOW
#   remediationSteps: [Make sure you can manage webhooks for the repository, Go to the repository settings page, Select "Webhooks", Press on the insecure webhook, Confiure a secret, Click "Update webhook"]
#   requiredScopes: [read:repo_hook, repo]
#   threat:
#     - "Not using a webhook secret makes the service receiving the webhook unable to determine the authenticity of the request."
#     - "This allows attackers to masquerade as your repository, potentially creating an unstable or insecure state in other systems."
repository_webhook_no_secret[violated] := true {
	some index
	hook := input.hooks[index]
	not webhookUtils.has_secret(hook)
	violated := {
		"name": hook.name,
		"url": hook.url,
	}
}

# METADATA
# scope: rule
# title: Webhooks Should Be Configured To Use SSL
# description: Webhooks that are not configured with SSL enabled could expose your sofware to man in the middle attacks (MITM).
# custom:
#   requiredEnrichers: [hooksList]
#   severity: LOW
#   remediationSteps: [Make sure you can manage webhooks for the repository, Go to the repository settings page, Select "Webhooks", Verify url starts with https, Press on the insecure webhook, Enable "SSL verfication", Click "Update webhook"]
#   requiredScopes: [read:repo_hook, repo]
#   threat:
#     - "If SSL verification is disabled, any party with access to the target DNS domain can masquerade as your designated payload URL, allowing it freely read and affect the response of any webhook request."
#     - "In the case of GitHub Enterprise Server instances, it may be sufficient only to control the DNS configuration of the network where the instance is deployed, as an attacker can redirect traffic to the target domain in your internal network directly to them, and this is often much easier than compromising an internet-facing domain."
repository_webhook_doesnt_require_ssl[violated] := true {
	some index
	hook := input.hooks[index]
	not webhookUtils.ssl_enabled(hook)
	violated := {
		"name": hook.name,
		"url": hook.url,
	}
}

# METADATA
# scope: rule
# title: Default Branch Should Be Protected
# description: Branch protection is not enabled for this repository’s default branch. Protecting branches ensures new code changes must go through a controlled merge process and allows enforcement of code review as well as other security tests. This issue is raised if the default branch protection is turned off.
# custom:
#   remediationSteps: [Make sure you have admin permissions, Go to the repo's settings page, Enter "Branches" tab, Under "Branch protection rules", Click "Add rule", Set "Branch name pattern" as the default branch name (usually "main" or "master"), Set desired protections, Click "Create" and save the rule]
#   severity: CRITICAL
#   requiredScopes: [repo]
#   prerequisites: [has_branch_protection_permission]
#   threat: Any contributor with write access may push potentially dangerous code to this repository, making it easier to compromise and difficult to audit.
default missing_default_branch_protection := true

missing_default_branch_protection := false {
	not is_null(input.repository.default_branch.branch_protection_rule)
}

missing_default_branch_protection := false {
    some index
    rule := input.rules_set[index]
    rule.type == "pull_request"
}

# METADATA
# scope: rule
# title: Default Branch Deletion Protection Should Be Enabled
# description: The history of the default branch is not protected against deletion for this repository.
# custom:
#   remediationSteps:
#     - Note: The remediation steps applys to legacy branch protections, rules set based protection should be updated from the rules set page
#     - Make sure you have admin permissions
#     - Go to the repo's settings page
#     - Enter "Branches" tab
#     - Under "Branch protection rules"
#     - Click "Edit" on the default branch rule
#     - Uncheck "Allow deletions", Click "Save changes"
#   severity: CRITICAL
#   requiredScopes: [repo]
#   prerequisites: [has_branch_protection_permission]
#   threat: Rewriting project history can make it difficult to trace back when bugs or security issues were introduced, making them more difficult to remediate.
default missing_default_branch_protection_deletion := true

missing_default_branch_protection_deletion := false {
	not input.repository.default_branch.branch_protection_rule.allows_deletions
}

missing_default_branch_protection_deletion := false {
    some index
    rule := input.rules_set[index]
    rule.type == "deletion"
}

# METADATA
# scope: rule
# title: Default Branch Should Not Allow Force Pushes
# description: The history of the default branch is not protected against changes for this repository. Protecting branch history ensures every change that was made to code can be retained and later examined. This issue is raised if the default branch history can be modified using force push.
# custom:
#   remediationSteps: ["Note: The remediation steps applys to legacy branch protections, rules set based protection should be updated from the rules set page", Make sure you have admin permissions, Go to the repo's settings page, Enter "Branches" tab, Under "Branch protection rules", Click "Edit" on the default branch rule, Uncheck "Allow force pushes", Click "Save changes"]
#   severity: HIGH
#   requiredScopes: [repo]
#   prerequisites: [has_branch_protection_permission]
#   threat: Rewriting project history can make it difficult to trace back when bugs or security issues were introduced, making them more difficult to remediate.
default missing_default_branch_protection_force_push := true

missing_default_branch_protection_force_push := false {
	not input.repository.default_branch.branch_protection_rule.allows_force_pushes
}

missing_default_branch_protection_force_push := false {
    some index
    rule := input.rules_set[index]
    rule.type == "non_fast_forward"
}

# METADATA
# scope: rule
# title: Default Branch Should Require All Checks To Pass Before Merge
# description: Branch protection is enabled. However, the checks which validate the quality and security of the code are not required to pass before submitting new changes. The default check ensures code is up-to-date in order to prevent faulty merges and unexpected behaviors, as well as other custom checks that test security and quality. It is advised to turn this control on to ensure any existing or future check will be required to pass.
# custom:
#   remediationSteps: ["Note: The remediation steps applys to legacy branch protections, rules set based protection should be updated from the rules set page", Make sure you have admin permissions, Go to the repo's settings page, Enter "Branches" tab, Under "Branch protection rules", Click "Edit" on the default branch rule, Check "Require status checks to pass before merging", "Add the required checks that must pass before merging (tests, lint, etc...)", Click "Save changes"]
#   severity: MEDIUM
#   requiredScopes: [repo]
#   prerequisites: [has_branch_protection_permission]
#   threat: Not defining a set of required status checks can make it easy for contributors to introduce buggy or insecure code as manual review, whether mandated or optional, is the only line of defense.
default requires_status_checks := true

requires_status_checks := false {
	input.repository.default_branch.branch_protection_rule.requires_status_checks
}

requires_status_checks := false {
    some index
    rule := input.rules_set[index]
    rule.type == "required_status_checks"
    count(rule.parameters.required_status_checks) > 0
}

# METADATA
# scope: rule
# title: Default Branch Should Require Branches To Be Up To Date Before Merge
# description: Status checks are required, but branches that are not up to date can be merged. This can result in previously remediated issues being merged in over fixes.
# custom:
#   remediationSteps: ["Note: The remediation steps applys to legacy branch protections, rules set based protection should be updated from the rules set page", Make sure you have admin permissions, Go to the repo's settings page, Enter "Branches" tab, Under "Branch protection rules", Click "Edit" on the default branch rule, Check "Require status checks to pass before merging", Check "Require branches to be up to date before merging", Click "Save changes"]
#   severity: MEDIUM
#   requiredScopes: [repo]
#   prerequisites: [has_branch_protection_permission]
#   threat: Required status checks may be failing on the latest version after passing on an earlier version of the code, making it easy to commit buggy or otherwise insecure code.
default requires_branches_up_to_date_before_merge := true

requires_branches_up_to_date_before_merge := false {
	input.repository.default_branch.branch_protection_rule.requires_status_checks
	input.repository.default_branch.branch_protection_rule.requires_strict_status_checks
}

requires_branches_up_to_date_before_merge := false {
    some index
    rule := input.rules_set[index]
    rule.type == "required_status_checks"
    count(rule.parameters.required_status_checks) > 0
    rule.parameters.strict_required_status_checks_policy
}

# METADATA
# scope: rule
# title: Default Branch Should Require New Code Changes After Approval To Be Re-Approved
# description: This security control prevents merging code that was approved but later on changed. Turning it on ensures any new changes must be reviewed again. This setting is part of the branch protection and code-review settings, and hardens the review process. If turned off - a developer can change the code after approval, and push code that is different from the one that was previously allowed. This option is found in the branch protection setting for the repository.
# custom:
#   remediationSteps: ["Note: The remediation steps applys to legacy branch protections, rules set based protection should be updated from the rules set page", Make sure you have admin permissions, Go to the repo's settings page, Enter "Branches" tab, Under "Branch protection rules", Click "Edit" on the default branch rule, Check "Require a pull request before merging", Check "Dismiss stale pull request approvals when new commits are pushed", Click "Save changes"]
#   severity: MEDIUM
#   requiredScopes: [repo]
#   prerequisites: [has_branch_protection_permission]
#   threat: Buggy or insecure code may be committed after approval and will reach the main branch without review. Alternatively, an attacker can attempt a just-in-time attack to introduce dangerous code just before merge.
default dismisses_stale_reviews := true

dismisses_stale_reviews := false {
	input.repository.default_branch.branch_protection_rule.dismisses_stale_reviews
}

dismisses_stale_reviews := false {
    some index
	rule := input.rules_set[index]
	rule.type == "pull_request"
	rule.parameters.dismiss_stale_reviews_on_push
}

# METADATA
# scope: rule
# title: Default Branch Should Require Code Review
# description: In order to comply with separation of duties principle and enforce secure code practices, a code review should be mandatory using the source-code-management system's built-in enforcement. This option is found in the branch protection setting of the repository.
# custom:
#   remediationSteps: ["Note: The remediation steps applys to legacy branch protections, rules set based protection should be updated from the rules set page", Make sure you have admin permissions, Go to the repo's settings page, Enter "Branches" tab, Under "Branch protection rules", Click "Edit" on the default branch rule, Check "Require a pull request before merging", Check "Require approvals", Set "Required number of approvals before merging" to 1 or more, Click "Save changes"]
#   severity: CRITICAL
#   requiredScopes: [repo]
#   prerequisites: [has_branch_protection_permission]
#   threat: Users can merge code without being reviewed, which can lead to insecure code reaching the main branch and production.
default code_review_not_required := true

code_review_not_required := false {
	input.repository.default_branch.branch_protection_rule.required_approving_review_count >= 1
}

code_review_not_required := false {
    some index
	rule := input.rules_set[index]
	rule.type == "pull_request"
	rule.parameters.required_approving_review_count >= 1
}

# METADATA
# scope: rule
# title: Default Branch Should Limit Code Review to Code-Owners
# description: It is recommended to require code review only from designated individuals specified in CODEOWNERS file. Turning this option on enforces that only the allowed owners can approve a code change. This option is found in the branch protection setting of the repository.
# custom:
#   remediationSteps: ["Note: The remediation steps applys to legacy branch protections, rules set based protection should be updated from the rules set page", Make sure you have admin permissions, Go to the repo's settings page, Enter "Branches" tab, Under "Branch protection rules", Click "Edit" on the default branch rule, Check "Require a pull request before merging", Check "Require review from Code Owners", Click "Save changes"]
#   severity: LOW
#   requiredScopes: [repo]
#   prerequisites: [has_branch_protection_permission]
#   threat: A pull request may be approved by any contributor with write access. Specifying specific code owners can ensure review is only done by individuals with the correct expertise required for the review of the changed files, potentially preventing bugs and security risks.
default code_review_not_limited_to_code_owners := true

code_review_not_limited_to_code_owners := false {
	input.repository.default_branch.branch_protection_rule.requires_code_owner_reviews
}

code_review_not_limited_to_code_owners := false {
    some index
	rule := input.rules_set[index]
	rule.type == "pull_request"
	rule.parameters.require_code_owner_review
}

# METADATA
# scope: rule
# title: Default Branch Should Require Linear History
# description: Prevent merge commits from being pushed to protected branches.
# custom:
#    remediationSteps: ["Note: The remediation steps applys to legacy branch protections, rules set based protection should be updated from the rules set page", Make sure you have admin permissions, Go to the repo's settings page, Enter "Branches" tab, Under "Branch protection rules", Click "Edit" on the default branch rule, Check "Require linear history", Click "Save changes"]
#    severity: MEDIUM
#    requiredScopes: [repo]
#    prerequisites: [has_branch_protection_permission]
#    threat: Having a non-linear history makes it harder to reverse changes, making recovery from bugs and security risks slower and more difficult.
default non_linear_history := true

non_linear_history := false {
	input.repository.default_branch.branch_protection_rule.requires_linear_history
}

non_linear_history := false {
    some index
	rule := input.rules_set[index]
	rule.type == "required_linear_history"
}

# METADATA
# scope: rule
# title: Default Branch Should Require All Conversations To Be Resolved Before Merge
# description: Require all Pull Request conversations to be resolved before merging. Check this to avoid bypassing/missing a Pull Reuqest comment.
# custom:
#    remediationSteps: ["Note: The remediation steps applys to legacy branch protections, rules set based protection should be updated from the rules set page", Make sure you have admin permissions, Go to the repo's settings page, Enter "Branches" tab, Under "Branch protection rules", Click "Edit" on the default branch rule, Check "Require conversation resolution before merging", Click "Save changes"]
#    severity: MEDIUM
#    requiredScopes: [repo]
#    prerequisites: [has_branch_protection_permission]
#    threat: Allowing the merging of code without resolving all conversations can promote poor and vulnerable code, as important comments may be forgotten or deliberately ignored when the code is merged.
default no_conversation_resolution := true

no_conversation_resolution := false {
	input.repository.default_branch.branch_protection_rule.requires_conversation_resolution
}

no_conversation_resolution := false {
    some index
	rule := input.rules_set[index]
	rule.type == "pull_request"
	rule.parameters.required_review_thread_resolution
}

# METADATA
# scope: rule
# title: Default Branch Should Require All Commits To Be Signed
# description: Require all commits to be signed and verified
# custom:
#    remediationSteps: ["Note: The remediation steps applys to legacy branch protections, rules set based protection should be updated from the rules set page", Make sure you have admin permissions, Go to the repo's settings page, Enter "Branches" tab, Under "Branch protection rules", Click "Edit" on the default branch rule, Check "Require signed commits", Click "Save changes"]
#    severity: LOW
#    requiredScopes: [repo]
#    prerequisites: [has_branch_protection_permission]
#    threat: A commit containing malicious code may be crafted by a malicious actor that has acquired write access to the repository to initiate a supply chain attack. Commit signing provides another layer of defense that can prevent this type of compromise.
default no_signed_commits := true

no_signed_commits := false {
	input.repository.default_branch.branch_protection_rule.requires_commit_signatures
}

no_signed_commits := false {
    some index
	rule := input.rules_set[index]
	rule.type == "required_signatures"
}

# METADATA
# scope: rule
# title: Default Workflow Token Permission Should Be Set To Read Only
# description: The default GitHub Action workflow token permission is set to read-write. When creating workflow tokens, it is highly recommended to follow the Principle of Least Privilege and force workflow authors to specify explicitly which permissions they need.
# custom:
#   remediationSteps:
#     - Make sure you have admin permissions
#     - Go to the org's settings page
#     - Enter "Actions - General" tab
#     - Under 'Workflow permissions'
#     - Select 'Read repository contents permission'
#     - Click 'Save'
#   severity: MEDIUM
#   requiredScopes: [repo]
#   threat: In case of token compromise (due to a vulnerability or malicious third-party GitHub actions), an attacker can use this token to sabotage various assets in your CI/CD pipeline, such as packages, pull-requests, deployments, and more.
default token_default_permissions_is_read_write := true

token_default_permissions_is_read_write := false {
	input.actions_token_permissions.default_workflow_permissions == "read"
}
