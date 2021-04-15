<template>
  <div id="app">
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
      <a class="navbar-brand" href="#">Postee UI</a>
    </nav>
    <div class="container">
      <router-view></router-view>
    </div>
  </div>
</template>

<script>
export default {
  name: "App",
  mounted() {
    this.$store.dispatch("load");
    this.$store.dispatch("loadStats");
  },
};
</script>

