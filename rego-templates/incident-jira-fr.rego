package postee.incident.jira.fr

import data.postee.with_default

title:="Détection d'incident"


tpl:=`
*Description :* %s
*Catégorie :* %s
*Score de gravité :* %v
*Détails bruts :* %v
*Nom de la politique de réponse :* %s
*Portées d'application de la politique de réponse :* %s
*Voir plus :* %s
`

result = msg {
    msg := sprintf(tpl, [
    input.name,
    input.category,
	input.severity_score,
    input.data,
    input.response_policy_name,
    concat(", ", with_default(input, "application_scope", [])),
    with_default(input, "url", "")
    ])
}
