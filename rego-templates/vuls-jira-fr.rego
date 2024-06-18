package postee.vuls.jira.fr

import data.postee.by_flag
import data.postee.with_default
import data.postee.flat_array #converts [[{...},{...}], [{...},{...}]] to [{...},{...},{...},{...}]
import data.postee.array_concat

title = sprintf("rapport de scan de vulnérabilité %s", [input.image])


tpl:=`
*Nom de l'image:* %s
*Enregistrement:* %s
%s
%s
%s

%v

%v

*Nom de la stratégie de réponse*: %s
*Champs d’application de la stratégie de réponse*: %s
`

check_failed(item) = false {
    not item.failed
}
check_failed(item) = true {
    item.failed
}

assurance_controls(inp) = l {
    headers := [ "\n*Assurance controls*\n||*#\t*                        ||*Control*                       ||*Policy Name*                       ||*Status*                       ||\n" ]
    checks_performed:= flat_array([check |
                item := input.image_assurance_results.checks_performed[i]
                check := [ sprintf("|%d|%s|%s|%s|\n", [i+1, item.control, item.policy_name, by_flag("FAIL", "PASS", check_failed(item))]) ]
    ])
    ll := array.concat(headers, checks_performed)
    l := concat("", ll)
}

result = msg {
    msg := sprintf(tpl, [
    input.image,
    input.registry,
	by_flag(
     "L'image est _*non conforme*_",
     "L'image est _*conforme*_",
     with_default(input.image_assurance_results, "disallowed", false)
    ),
	by_flag(
     "*Malware détecté:* Oui",
     "*Malware détecté:* Non",
     with_default(input.vulnerability_summary, "malware", 0) > 0 #reflects current logic
    ),
	by_flag(
	 "*Données sensibles trouvées:* Oui",
         "*Données sensibles trouvées:* Non",
     with_default(input.vulnerability_summary, "sensitive", 0) > 0 #reflects current logic
	),
    sprintf("\n*Résumé des vulnérabilités*\n||*Gravité*                        ||*Score*                       ||\n|Critique|%v|\n|Haut|%v|\n|Moyen|%v|\n|Faible|%v|\n|Négligeable|%v|\n", [
    format_int(with_default(input.vulnerability_summary,"critical",0), 10),
    format_int(with_default(input.vulnerability_summary,"high",0), 10),
    format_int(with_default(input.vulnerability_summary,"medium",0), 10),
    format_int(with_default(input.vulnerability_summary,"low",0), 10),
    format_int(with_default(input.vulnerability_summary,"negligible",0), 10)]),
    assurance_controls("input"),
    with_default(input, "response_policy_name", "absent"),
    concat(", ", with_default(input, "application_scope", []))
    ])
}
