<template>
  <div class="card mt-4">
    <!--        <h1>Details for plugin {{ $route.params.name }}</h1> -->
    <div class="card-header">
      {{ settings.type }}
    </div>
    <div class="card-body">
      <form @submit.prevent="doSubmit">
        <div class="form-group form-input">
          <label for="pluginInput">Name</label>
          <input
            type="input"
            :value="settings.name"
            name="name"
            @input="updateSettings"
            class="form-control"
            id="pluginInput"
          />
          <small id="aHelp" class="form-text text-muted"
            >Some details about A.</small
          >
        </div>
        <div class="form-group form-check">
          <input
            type="checkbox"
            class="form-check-input"
            id="pluginEnable"
            :checked="settings.enable"
            name="enable"
          />
          <label class="form-check-label" for="pluginEnable"
            >enable plugin</label
          >
        </div>
        <ul class="nav">
          <li class="nav-item">
            <button type="submit" class="btn btn-primary">Submit</button>
          </li>
          <li class="nav-item">
            <router-link :to="{ name: 'home' }" class="nav-link"
              >Cancel</router-link
            >
          </li>
        </ul>
      </form>
    </div>
  </div>
</template>
<script>
import { mapState } from "vuex";

export default {
  data() {
    return {
      id: "",
    };
  },
  computed: {
    ...mapState({
      settings(state) {
        const found = state.config.entries.filter(
          (item) => item.id === this.id
        );

        return found.length ? { ...found[0] } : {};
      },
    }),
  },
  methods: {
    doSubmit() {
      this.$store.commit("updateSettings", {
        value: this.settings,
        id: this.id,
      });
      this.$router.push({ name: "home" });
    },
    updateSettings(e) {
      const propName = e.target.attributes["name"].value;
      console.log(propName);
      this.settings[propName] = e.target.value;
    },
  },
  mounted() {
    this.id = this.$route.params.id;
  },
};
</script>