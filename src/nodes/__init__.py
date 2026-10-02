"""CMN-C1-197 node package — Cat 1 fixed-pipeline slots.

The architect-spec 6-step OWASP Agentic runtime anomaly pipeline mapped onto the
Cat 1 backbone slots (each step's logic preserved 1:1 in src/services/):

  initialize    S-1 trust + S-2 input validation
  pre_process   Step 1 EventStreamParse
  main          Steps 2-5 OWASPTaxonomyClassify → PolicyViolationDetect
                → SeverityScore → IncidentAlert
  post_process  Step 6 AuditLogWrite (S-3 mask + S-5 audit)
"""

from src.nodes.initialize_node import InitializeNode
from src.nodes.main_node import MainNode
from src.nodes.post_process_node import PostProcessNode
from src.nodes.pre_process_node import PreProcessNode

__all__ = [
    "InitializeNode",
    "PreProcessNode",
    "MainNode",
    "PostProcessNode",
]
