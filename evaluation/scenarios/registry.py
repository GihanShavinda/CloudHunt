from .compromised_key import SCENARIO as compromised_key
from .iam_privesc import SCENARIO as iam_privesc
from .assume_role_chain import SCENARIO as assume_role_chain
from .s3_exfiltration import SCENARIO as s3_exfiltration
from .defense_evasion import SCENARIO as defense_evasion
from .trust_policy_backdoor import SCENARIO as trust_policy_backdoor
from .benign_automation import SCENARIO as benign_automation
SCENARIOS = {s['id']: s for s in [compromised_key, iam_privesc, assume_role_chain, s3_exfiltration, defense_evasion, trust_policy_backdoor, benign_automation]}
