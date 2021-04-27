<template>
  <form class="form-signin" @submit.prevent="doSubmit">
    <h1 class="h3 mb-3 font-weight-normal">Please sign in</h1>
    <label for="username" class="sr-only">Username</label>
    <input
      type="username"
      id="username"
      class="form-control mb-3"
      v-model="username"
      placeholder="Username"
      required=""
      autofocus=""
    />
    <label for="password" class="sr-only">Password</label>
    <input
      type="password"
      id="inputPassword"
      class="form-control mb-3"
      v-model="password"
      v-on:keyup.enter="doSubmit"
      placeholder="Password"
      required=""
    />
    <div class="checkbox">
      <label> <input type="checkbox" value="remember-me" /> Remember me </label>
    </div>
    <button class="btn btn-lg btn-primary btn-block" type="submit">
      Sign in
    </button>
  </form>
</template>
<style>
.form-signin {
  width: 100%;
  max-width: 330px;
  padding: 15px;
  margin: 0 auto;
}
</style>
<script>
import { LOGIN_ACTION } from "../store/store";

export default {
  data() {
    return {
      username: "",
      password: "",
    };
  },
  methods: {
    doSubmit() {
      this.$store.dispatch(LOGIN_ACTION, {
        username: this.username,
        password: this.password,
      }).then(()=>{
        this.$router.push({ name: "home" })
      }).catch(()=>{});
    },
  },
};
</script>