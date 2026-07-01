# Design Red-Team Rubric

Score each UI change from 0 to 2 for each criterion. A score below 10 requires
revision before implementation continues.

| Criterion | 0 | 1 | 2 |
| --- | --- | --- | --- |
| Evidence first | Claims status without proof. | Shows partial evidence. | Shows exact evidence and missing evidence. |
| Safety clarity | Dangerous action looks normal. | Blocked state exists but vague. | Preview, block, approval, and rollback state are clear. |
| Distinctiveness | Generic SaaS dashboard. | Some unique surfaces. | Spatial, tactile DevDrop language is obvious. |
| Secret discipline | Could expose values. | Values hidden but policy unclear. | Values impossible to view and policy is explicit. |
| Generated-path clarity | Ignore policy hidden. | Policy mentioned. | Included/excluded paths are inspectable. |
| Machine topology | Machines are labels only. | Basic map. | Topology explains trust and freshness. |
| Copy precision | Vague pills or hype. | Mostly clear. | Specific, calm, non-panicky language. |

