import Vue from 'vue'
import Vuex from 'vuex'
import api from './../api'
import {router} from './../main'


const enrichId = entry => {
    entry.id = btoa(entry.type + '-' + entry.name)
}
Vue.use(Vuex)


export const LOAD_ACTION = "load"
export const LOGIN_ACTION = "login"
export const LOGOUT_ACTION = "logout"
export const LOAD_STATS_ACTION = "loadStats"
export const UPDATE_SETTINGS_ACTION = "updateSettings"
export const ADD_SETTINGS_ACTION = "addSettings"
export const REMOVE_SETTINGS_ACTION = "removeSettings"

export const USER_INFO_MUTATION = "updateUserInfo"
export const ERROR_MUTATION = "ajaxError"
export const CLEAR_ERROR_MUTATION = "clearAjaxError"
export const STATS_MUTATION = "updateStats"
export const CONFIG_MUTATION = "updateSettings"

export default new Vuex.Store({
    state: {
        config: {
            entries: [],
        },
        stats: {
        },
        error: {},
        userInfo: {
            authenticated: false
        }
    },
    actions: {
        [LOGIN_ACTION](context, { username, password }) {
            api.login(username, password).then(() => {
                context.commit(USER_INFO_MUTATION, { authenticated: true })
                context.commit(CLEAR_ERROR_MUTATION)
                router.push({ name: "home" });
            }).catch(error => {
                if (error.response.status === 401) {
                    context.commit(ERROR_MUTATION, "Invalid credentials")
                }
            })
        },
        [LOGOUT_ACTION](context) {
            api.logout().then(()=>{
                context.commit(USER_INFO_MUTATION, { authenticated: false })
                router.push({ name: "login" });
            }).catch(error => {
                context.commit(ERROR_MUTATION, error.response.data)
            })
        },
        [LOAD_ACTION](context) {
            api.getConfig().then((response) => {
                for (const entry of response.data) {
                    enrichId(entry)
                }
                context.commit(CONFIG_MUTATION, response.data)
            }).catch((error) => {
                context.commit(ERROR_MUTATION, error.response.data)
            })
        },
        [LOAD_STATS_ACTION](context) {
            api.getStats().then((response) => {
                context.commit(STATS_MUTATION, response.data)
            }).catch((error) => {
                context.commit(ERROR_MUTATION, error.response.data)
            })
        },
        [UPDATE_SETTINGS_ACTION](context, payload) {
            const entries = context.state.config.entries;
            const { value, id } = payload

            for (let i = 0; i < entries.length; i++) {
                if (entries[i].id == id) {
                    entries.splice(i, 1, value)
                }
            }

            api.saveConfig(entries).then(
                context.commit(CONFIG_MUTATION, entries)
            ).catch((error) => {
                context.commit(ERROR_MUTATION, error.response.data)
            })

        },
        [REMOVE_SETTINGS_ACTION](context, id) {
            const filtered = context.state.config.entries.filter(item => item.id != id)
            api.saveConfig(filtered).then(
                context.commit(CONFIG_MUTATION, filtered)
            ).catch((error) => {
                context.commit(ERROR_MUTATION, error.response.data)
            })
        },
        [ADD_SETTINGS_ACTION](context, settings) {
            const entries = context.state.config.entries
            enrichId(settings)
            entries.push(settings)
            api.saveConfig(entries).then(
                context.commit(CONFIG_MUTATION, entries)
            ).catch((error) => {
                context.commit(ERROR_MUTATION, error.response.data)
            })
        }
    },
    mutations: {
        [STATS_MUTATION](state, payload) {
            state.stats = { ...payload }
        },
        [CONFIG_MUTATION](state, entries) {
            state.config.entries = [...entries]
        },
        [USER_INFO_MUTATION](state, info) {
            state.userInfo = { ...info }
        },
        [ERROR_MUTATION](state, error) {
            state.error = { ...{ message: error } }
        },
        [CLEAR_ERROR_MUTATION](state) {
            state.error = {}
        }
    }
})