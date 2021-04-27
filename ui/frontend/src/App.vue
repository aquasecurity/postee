<template>
  <div id="app">
    <nav class="navbar navbar-expand-lg navbar-light bg-secondary mb-3">
      <a class="navbar-brand" href="#">Postee UI</a>
    </nav>

    <div class="container-fluid">
      <div class="row content">
        <div v-if="!isOnLogin" class="col-sm-2">
          <ul class="nav flex-column nav-pills">
            <li class="nav-item">
              <router-link
                active-class="active"
                :to="{ name: 'integrations' }"
                class="nav-link"
                >Integrations</router-link
              >
            </li>
            <li class="nav-item">
              <router-link
                active-class="active"
                :to="{ name: 'routes' }"
                class="nav-link"
                >Routes</router-link
              >
            </li>
            <li class="nav-item">
              <router-link
                active-class="active"
                :to="{ name: 'settings' }"
                class="nav-link"
                >Settings</router-link
              >
            </li>
            <li class="nav-item">
              <a class="nav-link" @click="doLogout" href="#">Logout</a>
            </li>
          </ul>
        </div>
        <div
          v-bind:class="[
            { 'col-sm-12': isOnLogin },
            { 'col-sm-9': !isOnLogin },
          ]"
        >
          <div v-if="error" class="alert alert-danger" role="alert">
            {{ error }}
          </div>
          <router-view></router-view>
        </div>
      </div>
    </div>
  </div>
</template>
<style>
</style>
<script>
import { mapState } from "vuex";
import {
  LOGIN_ACTION,
  LOGOUT_ACTION,
  CLEAR_ERROR_MUTATION,
  LOAD_ACTION,
  LOAD_STATS_ACTION,
} from "./store/store";

export default {
  name: "App",
  watch: {
    $route(to) {
      this.$store.commit(CLEAR_ERROR_MUTATION);
      if (to.name === "home" && !this.$store.state.config.outputs.length) {
        this.startLoading();
      }
      this.isOnLogin = to.name === "login";
    },
  },
  data() {
    return {
      isOnLogin: false,
    };
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
      if (!this.isOnLogin) {
        this.$store
          .dispatch(LOGIN_ACTION)
          .then(() => {
            this.startLoading();
          })
          .catch((error) => {
            if (!error) {
              //check failed - session is invalid
              this.$router.push({ name: "login" });
            }
          });
      }
    }
  },
};
</script>

