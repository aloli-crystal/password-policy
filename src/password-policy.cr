require "./password-policy/version"
require "./password-policy/use_case"
require "./password-policy/violation"
require "./password-policy/entropy"
require "./password-policy/policy"

# Password policies following the CNIL recommendation of 21 July 2022
# (délibération 2022-100).
#
# ```
# policy = PasswordPolicy::Policy.long # 14 characters, no special required
#
# policy.satisfies_use_case? # => true
# policy.entropy             # => 83.4 bits
#
# case policy.validate(submitted)
# when .empty? then accept
# else              reject_with(violations)
# end
# ```
#
# Two things this shard deliberately does not do:
#
# * *It does not hash.* Hashing belongs to the authentication stack that stores
#   the result — `marten-auth`, or `Crypto::Bcrypt` directly. Bundling the two
#   is what tied the rules this was extracted from to one web framework.
# * *It does not score an individual password.* `Policy#entropy` is the entropy
#   of the policy, across every password it admits. Scoring one chosen password
#   means estimating how guessable it is, which the CNIL names as the better
#   approach while declining to set a threshold, for want of tooling available
#   to French-speaking users. Use `Policy#forbidden` for the practical part of
#   that problem.
module PasswordPolicy
end
