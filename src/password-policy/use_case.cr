module PasswordPolicy
  # The three use cases of the CNIL recommendation of 21 July 2022
  # (délibération 2022-100), each with its own minimum entropy.
  #
  # The point of the 2022 revision is that a *policy* is judged on the entropy
  # it guarantees, not on a minimum length. Two policies of equal entropy are
  # equally acceptable, which leaves room to trade length against character
  # variety instead of imposing one shape on everybody.
  enum UseCase
    # A password on its own, with nothing limiting online attacks — a forum, a
    # blog. The strictest tier, because brute force is unimpeded.
    Alone

    # A password plus a mechanism limiting online attacks: delay after failed
    # attempts, a cap on tries per period, a CAPTCHA, lock-out after ten
    # failures. The CNIL calls this the most widespread case and cites
    # e-commerce, company accounts and webmail.
    #
    # An accounting application reachable over the web belongs here, provided
    # it actually implements such a mechanism — the lower bar is earned by that
    # measure, not granted by the use case.
    WithAccessRestriction

    # An unlock code for hardware the person holds themselves — a bank card, a
    # phone. Requires the hardware plus lock-out after three failed attempts.
    WithDeviceHeld

    # Minimum entropy in bits, as published by the CNIL.
    def minimum_entropy : Float64
      case self
      in Alone                 then 80.0
      in WithAccessRestriction then 50.0
      in WithDeviceHeld        then 13.0
      end
    end

    # The complementary measures this tier assumes are in place. Choosing a
    # tier without implementing them is not compliance, it is wishful thinking.
    def required_measures : String
      case self
      in Alone
        "advise the user on choosing a good password"
      in WithAccessRestriction
        "limit online attacks: access delay after repeated failures, a cap on " \
        "attempts per period, a CAPTCHA, or lock-out after ten failures"
      in WithDeviceHeld
        "hardware held by the person, plus lock-out after three failed attempts"
      end
    end
  end
end
