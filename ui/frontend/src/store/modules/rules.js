import api from "../../api"

function updateRules(context, rules) {
    api.saveConfig(api.toApiPayload(context, {rules})).then(
        context.commit("set", rules)
    ).catch((error) => {
        context.commit("error/set", error.response.data, {root:true})
    })
}

export default {
    namespaced: true,
    state: {all: []},
    actions: {
        update(context, payload) {
            const rules = context.state.all;
            const { value, name } = payload

            for (let i = 0; i < rules.length; i++) {
                if (rules[i].name == name) {
                    rules.splice(i, 1, value)
                }
            }
            updateRules(context, rules)
        },
        remove(context, name) {
            const rules = context.state.all.filter(item => item.name != name)

            updateRules(context, rules)
        },
        add(context, settings) {
            const rules = context.state.all
            rules.push(settings)

            updateRules(context, rules)
        },


    },
    mutations: {
        set(state, rules) {
            state.all = [...rules]
        },

    }
}