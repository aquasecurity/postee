<template>
  <div id="app">
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
      <a class="navbar-brand mr-auto" href="#">Postee UI</a>
      <a class="navbar-item" @click="doLogout" href="#">Logout</a>
    </nav>
    <div class="container">
      <div v-if="error" class="alert alert-danger" role="alert">
        {{ error }}
      </div>
      <router-view></router-view>
    </div>
  </div>
</template>

<script>
import { mapState } from "vuex";
import {
  LOGIN_ACTION,
  LOGOUT_ACTION,
  CLEAR_ERROR_MUTATION,
  LOAD_ACTION,
  LOAD_STATS_ACTION
} from "./store/store";

export default {
  name: "App",
  watch: {
    $route(to) {
      this.$store.commit(CLEAR_ERROR_MUTATION);
      if(to.name === 'home' && !this.$store.state.config.entries.length) {
        this.startLoading();
      }
    },
  },
  computed: {
    ...mapState({
      error(state) {
        return state.error.message;
      },
    }),
  },
  methods: {
    doLogout() {
      this.$store.dispatch(LOGOUT_ACTION);
    },
    startLoading() {
      this.$store.dispatch(LOAD_ACTION);
      this.$store.dispatch(LOAD_STATS_ACTION);
    },
  },
  mounted() {
    if (this.$store.state.userInfo.authenticated) {
      this.startLoading();
    } else {
      if (this.$router.currentRoute.name != "login") {
        this.$store.dispatch(LOGIN_ACTION).then(()=> {
          this.startLoading();
        }).catch(error=>{
          if (!error) { //check failed - session is invalid
            this.$router.push({ name: "login" })
          }
        })
      }
    }
  },
};
</script>

