import axios from "axios";

export default {
    getConfig: function () {
        return axios.get("/plugins")
    },
    saveConfig: function () {

    }
}