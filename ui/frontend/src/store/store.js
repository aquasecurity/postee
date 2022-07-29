import Vue from 'vue'
import Vuex from 'vuex'
import api from './../api'

import error from './modules/error.js'
import account from './modules/account.js'
import actions from './modules/actions.js'
import stats from './modules/stats.js'
import events from './modules/events.js'
import routes from './modules/routes.js'
import settings from './modules/settings.js'
import flags from './modules/flags.js'
import templates from './modules/templates.js'
import rules from './modules/rules.js'

Vue.use(Vuex)

export default new Vuex.Store({
    modules: {
        error,
        actions,
        account,
        stats,
        events,
        routes,
        settings,
        flags,
        templates,
        rules
    },
    getters: {
        getAppState(state) {
            return state
        }
    },
    actions: {
        load(context) {
            api.getConfig().then((response) => {
                const data = response.data
                // console.log(data.rules)
                const settings = {
                    name: data.name,
                    AquaServer: data.AquaServer,
                    Delete_Old_Data: data.Delete_Old_Data,
                    DbVerifyInterval: data.DbVerifyInterval,
                    Max_DB_Size: data.Max_DB_Size
                }
                data.actions && context.commit("actions/set", data.actions)
                data.routes && context.commit("routes/set", data.routes)
                data.templates && context.commit("templates/set", data.templates)
                data.events && context.commit("events/set", data.events)
                data.rules && context.commit("rules/set", data.rules)
                context.commit("settings/set", settings)
                context.commit("flags/set", { loaded: true })
            }).catch((error) => {
                if (error.response) {
                    context.commit("error/set", error.response.data)
                } else {
                    console.error(error)
                }
            })
        }
    }

})