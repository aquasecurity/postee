package scanservice

func BuildMapContent(title, description, name string) map[string]string {
	content := make(map[string]string)
	content["name"] = name
	content["title"] = title
	content["description"] = description
	return content
}
