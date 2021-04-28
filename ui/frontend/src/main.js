import Vue from 'vue'
import VueRouter from 'vue-router'
import App from './App.vue'
import Integrations from './components/Integrations.vue'
import LoginForm from './components/LoginForm.vue'
import PluginDetails from './components/PluginDetails.vue'
import RouteDetails from './components/RouteDetails.vue'
import Routes from './components/Routes.vue'
import TemplateDetails from './components/TemplateDetails.vue'
import Templates from './components/Templates.vue'
import Settings from './components/Settings.vue'
import { BootstrapVue, BootstrapVueIcons } from 'bootstrap-vue'
import store from './store/store'
import 'bootstrap/dist/css/bootstrap.css'
import 'bootstrap-vue/dist/bootstrap-vue.css'

Vue.use(BootstrapVue);
Vue.use(BootstrapVueIcons);
Vue.use(VueRouter);

const routes = [
  { name: 'home', path: '/', redirect: '/integrations' },
  { name: 'integrations', path: '/integrations', component: Integrations },
  { name: 'routes', path: '/routes', component: Routes },
  { name: 'add-route', path: '/route', component: RouteDetails },
  { name: 'route', path: '/route/:name', component: RouteDetails },
  { name: 'settings', path: '/settings', component: Settings },
  { name: 'login', path: '/login', component: LoginForm },
  { name: 'add-plugin', path: '/plugin', component: PluginDetails },
  { name: 'plugin', path: '/plugin/:name', component: PluginDetails },

  { name: 'templates', path: '/templates', component: Templates },
  { name: 'add-template', path: '/template', component: TemplateDetails },
  { name: 'template', path: '/template/:name', component: TemplateDetails }
];

export const router = new VueRouter({
  routes, mode: 'history'
});

new Vue({
  router,
  store,
  render: h => h(App),
}).$mount('#app')
