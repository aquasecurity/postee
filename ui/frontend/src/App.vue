<template>
  <div id="app">
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
      <a class="navbar-brand" href="#">Postee UI</a>
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

export default {
  name: "App",
  computed: {
    ...mapState({
      error(state) {
        return state.error;
      },
    }),
  },
  mounted() {
    this.$store.dispatch("load");
    this.$store.dispatch("loadStats");
  },
};
</script>

