import Vue from 'vue'
import Vuex from 'vuex'
import api from './../api'


const enrichId = entry => {
    entry.id = btoa(entry.type + '-' + entry.name)
}
Vue.use(Vuex)


export const LOAD_ACTION = "load"
export const LOGIN_ACTION = "login"
export const LOAD_STATS_ACTION = "loadStats"
export const UPDATE_SETTINGS_ACTION = "updateSettings"
export const ADD_SETTINGS_ACTION = "addSettings"
export const REMOVE_SETTINGS_ACTION = "removeSettings"

export default new Vuex.Store({
    state: {
        config: {
            entries: [],
        },
        stats: {
        },
        error: undefined,
        userInfo: {
            authenticated: false
        }
    },
    actions: {
        [LOGIN_ACTION](context, { username, password }) {
            api.login(username, password).then(() => {
                context.commit('updateUserInfo', { authenticated: true })
            }).catch(error => {
                if (error.response.status === 401) {
                    console.log(context);
                }
            })
        },
        [LOAD_ACTION](context) {
            api.getConfig().then((response) => {
                for (const entry of response.data) {
                    enrichId(entry)
                }
                context.commit('updateSettings', response.data)
            }).catch((error) => {
                context.commit('ajaxError', error.response.data)
            })
        },
        [LOAD_STATS_ACTION](context) {
            api.getStats().then((response) => {
                context.commit('loadStats', response.data)
            }).catch((error) => {
                context.commit('ajaxError', error.response.data)
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
                context.commit('updateSettings', entries)
            ).catch((error) => {
                context.commit('ajaxError', error.response.data)
            })

        },
        [REMOVE_SETTINGS_ACTION](context, id) {
            const filtered = context.state.config.entries.filter(item => item.id != id)
            api.saveConfig(filtered).then(
                context.commit('updateSettings', filtered)
            ).catch((error) => {
                context.commit('ajaxError', error.response.data)
            })
        },
        [ADD_SETTINGS_ACTION](context, settings) {
            const entries = context.state.config.entries
            enrichId(settings)
            entries.push(settings)
            api.saveConfig(entries).then(
                context.commit('updateSettings', entries)
            ).catch((error) => {
                context.commit('ajaxError', error.response.data)
            })
        }
    },
    mutations: {
        loadStats(state, payload) {
            state.stats = { ...payload }
        },
        updateSettings(state, entries) {
            state.config.entries = [...entries]
        },
        updateUserInfo(state, info) {
            state.userInfo = { ...info }
        },
        ajaxError(state, error) {
            Vue.set(state, 'error', error)
        }
    }
})