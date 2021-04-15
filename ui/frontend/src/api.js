import axios from "axios";

export default {
    getConfig: function () {
        return axios.get("/plugins")
    },
    getStats: function () {
        return axios.get("/plugins/stats")
    },
    saveConfig: function (settings) {
        return axios.post("/update", settings) //TODO use same resource for both

    }
}