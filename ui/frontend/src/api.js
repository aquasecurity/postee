import axios from "axios";

export default {
    getConfig: function () {
        return axios.get("/api/plugins")
    },
    getStats: function () {
        return axios.get("/api/plugins/stats")
    },
    saveConfig: function (settings) {
        return axios.post("/api/update", settings) //TODO use same resource for both

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