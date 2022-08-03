<template>

  <div id="app">
    <b-navbar toggleable="lg" type="dark" variant="primary" class="navbar-expand-lg mb-3">
      <b-navbar-brand href="#">Postee</b-navbar-brand>
    </b-navbar>

    <div>
      <v-tour name="myTour" :callbacks="tourCallbacks" :steps="steps" :options="{ highlight: false }"></v-tour>
    </div>

    <div class="container-fluid">
      <div class="row content">
        <div v-if="!isOnLogin" class="col-sm-2">
          <ul class="nav flex-column nav-pills">
            <li class="nav-item">
              <router-link
                  active-class="active"
                  :to="{ name: 'routes' }"
                  class="nav-link"
                  id="routes"
              >Routes</router-link
              >
            </li>
            <li class="nav-item">
              <router-link
                active-class="active"
                :to="{ name: 'actions' }"
                class="nav-link"
                >Actions</router-link
              >
            </li>
            <li class="nav-item">
              <router-link
                active-class="active"
                :to="{ name: 'templates' }"
                class="nav-link"
                >Templates</router-link
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
              <router-link
                  active-class="active"
                  :to="{ name: 'events' }"
                  class="nav-link"
                  id="events"
                >Events</router-link
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

export default {
  name: "App",
  watch: {
    $route(to) {
      this.$store.commit("error/clear");
      if (["home", "routes"].indexOf(to.name) >= 0 && !this.$store.state.flags.all.loaded) {
        this.startLoading();
      }
    },
  },
  data() {
    return {
      tourCallbacks: {
        onStop: this.stopTour,
      },
      steps: [
        {
          target: '#routes',
          content: "Routes are scenarios that can occur based on input events",
          params: {
            enableScrolling: false,
          },
        },
        {
          target: "#add-route",
          content: "Let's begin by adding a new route",
          params: {
            enableScrolling: false,
          },
        },
        {
          target: "#name",
          content: "Start by giving it a name",
          params: {
            enableScrolling: false,
            placement: 'left',
          }
        },
        {
          target: "#select-input-policies",
          content: "Policies define when a route will be triggered",
          params: {
            enableScrolling: false,
            placement: 'left',
          }
        },
        {
          target: "#actions",
          content: "When a policy is triggered, <strong>Actions</strong> are taken",
          params: {
            enableScrolling: false,
            placement: 'left',
          }
        },
        {
          target: "#submit",
          content: "Go ahead and save this route",
          params: {
            enableScrolling: false,
          },
        },
        {
          target: "#events",
          content: "Let's check some incoming events",
          params: {
            placement: "right",
          }
        },
        {
          target: "#event-list",
          content: "Expand to see details"
        },
        {
          target: "",
          content: `You did it! Browse full docs at: <a href="https://aquasecurity.github.io/postee/latest/" target="_blank">Postee Docs</a>`
        }
      ]
    };
  },
  computed: {
    ...mapState({
      error(state) {
        return state.error.message;
      },
    }),
    isOnLogin() {
      return this.$route.name === 'login'
    }
  },
  methods: {
    doLogout() {
      this.$store.dispatch("account/logout");
    },
    startLoading() {
      this.$store.dispatch("load");
      this.$store.dispatch("stats/load");
      this.$store.dispatch("events/load");
      this.startTour();
    },
    startTour(){
        if (!localStorage.getItem('disable-tour')){
          this.$tours['myTour'].start()
      }else {
          this.$tours['myTour'].finish()
        }
    },
    stopTour(){
      if (!localStorage.getItem('disable-tour')) {
        localStorage.setItem('disable-tour', 'true');
      }
    }
  },
  mounted() {
    if (this.$store.state.account.authenticated) {
      this.startLoading();
    } else {
      if (!this.isOnLogin) {
        this.$store
          .dispatch("account/login")
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

