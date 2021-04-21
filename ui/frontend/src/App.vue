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
import { LOGOUT_ACTION } from "./store/store";

export default {
  name: "App",
  computed: {
    ...mapState({
      error(state) {
        return state.error.message;
      }
    }),
  },
  methods : {
    doLogout() {
      this.$store.dispatch(LOGOUT_ACTION);
    }
  }
};
</script>

