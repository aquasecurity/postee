import Vue from 'vue'
import VueRouter from 'vue-router';
import Vuex from 'vuex';
import App from './App.vue'
import Home from './components/Home.vue'
import PluginDetails from './components/PluginDetails.vue';
import api from './api'

Vue.use(VueRouter);
Vue.use(Vuex)

const enrichId = entry => {
  entry.id = btoa(entry.type + '-' + entry.name)
}

const store = new Vuex.Store({
  state: {
    config: {
      entries: []
    }
  },
  actions: {
    load(context) {
      api.getConfig().then((response) => {
        context.commit('load', response.data)
      })
    }

  },
  mutations: {
    load(state, payload) {
      const entries = [...payload]

      for (const entry of entries) {
        enrichId(entry)
      }

      state.config = {
        entries
      }

    },
    updateSettings(state, payload) {
      const { value, id } = payload
      for (let i = 0; i < state.config.entries.length; i++) {
        if (state.config.entries[i].id == id) {
          state.config.entries.splice(i, 1, value)
        }

      }
      //handle addition
      //call api to persist

    },
    removeSettings(state, id) {
      const filtered = state.config.entries.filter(item => item.id != id)
      state.config.entries = [...filtered]
    },
    addSettings(state, settings) {
      const entries = state.config.entries
      enrichId(settings)
      entries.push(settings)
      state.config.entries = [...entries]
    }
  }
})

const routes = [
  { name: 'home', path: '/', component: Home },
  { name: 'add-plugin', path: '/plugin', component: PluginDetails },
  { name: 'plugin', path: '/plugin/:id', component: PluginDetails }
];

const router = new VueRouter({
  routes, mode: 'history'
});

//Vue.config.productionTip = false
new Vue({
  router,
  store,
  render: h => h(App),
}).$mount('#app')
