import Vue from 'vue'
import VueRouter from 'vue-router';
import App from './App.vue'
import Home from './components/Home.vue'
import PluginDetails from './components/PluginDetails.vue';

Vue.use(VueRouter);

const routes = [
  {name: 'home', path: '/', component: Home},
  {name: 'add-plugin', path: '/plugin', component: PluginDetails},
  {name: 'plugin', path: '/plugin/:name', component: PluginDetails}
];

const router = new VueRouter({
  routes, mode: 'history'
});

//Vue.config.productionTip = false
new Vue({
  router,
  render: h => h(App),
}).$mount('#app')
