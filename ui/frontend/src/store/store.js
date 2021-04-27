import Vue from 'vue'
import Vuex from 'vuex'
import api from './../api'
import { router } from './../main'


Vue.use(Vuex)


export const LOAD_ACTION = "load"
export const TEST_ACTION = "test"
export const LOGIN_ACTION = "login"
export const LOGOUT_ACTION = "logout"
export const LOAD_STATS_ACTION = "loadStats"
export const UPDATE_OUTPUT_ACTION = "updateOutput"
export const UPDATE_ROUTE_ACTION = "updateRoute"
export const REMOVE_ROUTE_ACTION = "removeRoute"
export const ADD_ROUTE_ACTION = "addRoute"
export const UPDATE_SETTINGS_ACTION = "updateSettings"
export const ADD_OUTPUT_ACTION = "addOutput"
export const REMOVE_OUTPUT_ACTION = "removeOutput"

export const USER_INFO_MUTATION = "updateUserInfo"
export const ERROR_MUTATION = "ajaxError"
export const CLEAR_ERROR_MUTATION = "clearAjaxError"
export const STATS_MUTATION = "updateStats"
export const CONFIG_MUTATION = "mutateConfig"
export const ROUTES_MUTATION = "mutateRoutes"
export const OUTPUTS_MUTATION = "mutateOutputs"
export const SETTINGS_MUTATION = "mutateSettings"

export default new Vuex.Store({
    state: {
        config: {
            general: {},
            routes: [],
            templates: [],
            outputs: []
        },
        stats: {
        },
        error: {},
        userInfo: {
            authenticated: false
        }
    },
    actions: {
        [TEST_ACTION](context, settings) {
            return new Promise((resolve, reject) => {
                api.test(settings).then(() => {
                    context.commit(CLEAR_ERROR_MUTATION)
                    resolve();
                }).catch(error => {
                    if (error.response) {
                        context.commit(ERROR_MUTATION, error.response.data)
                        reject(error.response.data);
                    } else {
                        console.error(error)
                        reject(error);
                    }
                })
            })
        },
        [LOGIN_ACTION](context, payload) {
            const { username, password } = payload || {}
            return new Promise((resolve, reject) => {
                api.login(username, password).then(() => {
                    context.commit(USER_INFO_MUTATION, { authenticated: true })
                    context.commit(CLEAR_ERROR_MUTATION)
                    resolve()
                }).catch(error => {
                    if (username && password) {
                        const errorMsg = error.response.status === 401 ? "Invalid credentials" : error.response.data;
                        context.commit(ERROR_MUTATION, errorMsg)
                        reject(errorMsg)
                    } else {
                        reject() //just checking
                    }
                })
            })
        },
        [LOGOUT_ACTION](context) {
            api.logout().then(() => {
                context.commit(USER_INFO_MUTATION, { authenticated: false })
                router.push({ name: "login" });
            }).catch(error => {
                context.commit(ERROR_MUTATION, error.response.data)
            })
        },
        [LOAD_ACTION](context) {
            api.getConfig().then((response) => {
                const data = response.data
                const config = {
                    general: {
                        name: data.name,
                        AquaServer: data.AquaServer,
                        Delete_Old_Data: data.Delete_Old_Data,
                        DbVerifyInterval: data.DbVerifyInterval
                    },
                    outputs: data.outputs,
                    routes: data.routes

                }
                context.commit(CONFIG_MUTATION, config)
            }).catch((error) => {
                if (error.response) {
                    context.commit(ERROR_MUTATION, error.response.data)
                } else {
                    console.error(error)
                }
            })
        },
        [LOAD_STATS_ACTION](context) {
            api.getStats().then((response) => {
                context.commit(STATS_MUTATION, response.data)
            }).catch((error) => {
                context.commit(ERROR_MUTATION, error.response.data)
            })
        },
        [UPDATE_ROUTE_ACTION](context, payload) {
            const routes = context.state.config.routes;
            const { value, name } = payload

            for (let i = 0; i < routes.length; i++) {
                if (routes[i].name == name) {
                    routes.splice(i, 1, value)
                }
            }
            const config = { ...context.state.config, routes, general : undefined }

            api.saveConfig(config).then( //entire config is saved
                context.commit(ROUTES_MUTATION, routes)
            ).catch((error) => {
                context.commit(ERROR_MUTATION, error.response.data)
            })
        },
        [UPDATE_OUTPUT_ACTION](context, payload) {
            const outputs = context.state.config.outputs;
            const { value, name } = payload

            for (let i = 0; i < outputs.length; i++) {
                if (outputs[i].name == name) {
                    outputs.splice(i, 1, value)
                }
            }
            const config = { ...context.state.config, outputs, general : undefined }

            api.saveConfig(config).then( //entire config is saved
                context.commit(OUTPUTS_MUTATION, outputs)
            ).catch((error) => {
                context.commit(ERROR_MUTATION, error.response.data)
            })

        },
        [UPDATE_SETTINGS_ACTION](context, payload) {
            const config = { ...context.state.config, ...payload }
            config.general = undefined

            api.saveConfig(config).then( //entire config is saved
                context.commit(SETTINGS_MUTATION, payload)
            ).catch((error) => {
                context.commit(ERROR_MUTATION, error.response.data)
            })

        },

        [REMOVE_OUTPUT_ACTION](context, name) {
            const filtered = context.state.config.outputs.filter(item => item.name != name)
            const config = { ...context.state.config, outputs : filtered, general : undefined }
            api.saveConfig(config).then(
                context.commit(OUTPUTS_MUTATION, filtered)
            ).catch((error) => {
                context.commit(ERROR_MUTATION, error.response.data)
            })
        },
        [ADD_OUTPUT_ACTION](context, settings) {
            const outputs = context.state.config.outputs
            outputs.push(settings)
            const config = { ...context.state.config, outputs, general : undefined }
            api.saveConfig(config).then(
                context.commit(OUTPUTS_MUTATION, outputs)
            ).catch((error) => {
                context.commit(ERROR_MUTATION, error.response.data)
            })
        },
        [REMOVE_ROUTE_ACTION](context, name) {
            const filtered = context.state.config.routes.filter(item => item.name != name)
            const config = { ...context.state.config, routes: filtered, general : undefined }

            api.saveConfig(config).then(
                context.commit(ROUTES_MUTATION, filtered)
            ).catch((error) => {
                context.commit(ERROR_MUTATION, error.response.data)
            })
        },
        [ADD_ROUTE_ACTION](context, route) {
            const routes = context.state.config.routes
            routes.push(route)
            const config = { ...context.state.config, routes, general : undefined }
            api.saveConfig(config).then(
                context.commit(ROUTES_MUTATION, routes)
            ).catch((error) => {
                context.commit(ERROR_MUTATION, error.response.data)
            })
        }
    },
    mutations: {
        [STATS_MUTATION](state, payload) {
            state.stats = { ...payload }
        },
        [CONFIG_MUTATION](state, config) {
            state.config = { ...config }
        },
        [SETTINGS_MUTATION](state, config) {
            state.config.general = { ...config }
        },
        [OUTPUTS_MUTATION](state, outputs) {
            state.config.outputs = [...outputs]
        },
        [ROUTES_MUTATION](state, routes) {
            state.config.routes = [...routes]
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