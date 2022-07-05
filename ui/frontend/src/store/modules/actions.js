import api from "../../api"
function updateActions(context, actions) {
    api.saveConfig(api.toApiPayload(context, {actions})).then( //entire config is saved
        context.commit("set", actions)
    ).catch((error) => {
        context.commit("error/set", error.response.data, {root:true})
    })
}
export default {
    namespaced: true,
    state: {all: []},
    actions: {
        test(context, settings) {
            return new Promise((resolve, reject) => {
                api.test(settings).then(() => {
                    context.commit("error/clear", undefined, {root:true})
                    resolve();
                }).catch(error => {
                    if (error.response) {
                        context.commit("error/set", error.response.data, {root:true})
                        reject(error.response.data);
                    } else {
                        console.error(error)
                        reject(error);
                    }
                })
            })
        },

        update(context, payload) {
            const actions = context.state.all;
            const { value, name } = payload

            for (let i = 0; i < actions.length; i++) {
                if (actions[i].name == name) {
                    actions.splice(i, 1, value)
                }
            }
            updateActions(context, actions)
        },
        remove(context, name) {
            const actions = context.state.all.filter(item => item.name != name)

            updateActions(context, actions)
        },
        add(context, settings) {
            const actions = context.state.all
            actions.push(settings)

            updateActions(context, actions)
        },


    },
    mutations: {
        set(state, actions) {
            state.all = [...actions]
        },

    }
}