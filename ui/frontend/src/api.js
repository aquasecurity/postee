import axios from "axios";
import yaml from "js-yaml";

const transformYaml = (response) => {
    const json = yaml.load(response)
    console.log(json)
    return json
}

export default {
    getConfig: function () {
        return axios.get("/api/config", {transformResponse: transformYaml})
    },
    getStats: function () {
        return axios.get("/api/plugins/stats")
    },
    saveConfig: function (settings) {
        const yamlObj = yaml.dump(settings)
        return axios.post("/api/config", yamlObj)

    },
    test: function (settings) {
        return axios.post("/api/test", settings)

    },
    login: function (username, password) {
        const bodyFormData = new FormData();

        bodyFormData.append('username', username ? username : "");
        bodyFormData.append('password', password ? password : "");

        return axios.post("/api/login", bodyFormData)

    },
    logout: function () {
        return axios.get("/api/logout")
    }
}