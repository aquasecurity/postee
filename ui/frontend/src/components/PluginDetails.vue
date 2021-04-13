<template>
  <div class="card mt-4">
    <!--        <h1>Details for plugin {{ $route.params.name }}</h1> -->
    <div class="card-header">
      {{ settings.type }}
    </div>
    <div class="card-body">
      <form @submit.prevent="doSubmit">
        <div class="form-group form-input">
          <label for="pluginType">Type</label>
          <select
            class="form-select mx-2"
            :value="settings.type"
            aria-label="Default select example"
            id="pluginType"
            name="type"
            @input="updateSettings"
          >
            <option value="common">Common</option>
            <option value="email">Email</option>
            <option value="jira">Jira</option>
            <option value="slack">Slack</option>
            <option value="teams">Teams</option>
            <option value="webhook">Webhook</option>
            <option value="splunk">Splunk</option>
            <option value="serviceNow">ServiceNow</option>
          </select>
          <small id="aHelp" class="form-text text-muted"
            >Type of the plugin.</small
          >
        </div>
        <PluginProperty
          :id="'name'"
          :label="'Name'"
          :value="settings.name"
          :name="'name'"
          :show="!isCommon"
          :inputHandler="updateSettings"
        >
        </PluginProperty>
        <PluginProperty
          :id="'url'"
          :label="'Url'"
          :value="settings.url"
          :name="'url'"
          :description="getUrlDescription"
          :show="showUrl"
          :inputHandler="updateSettings"
        >
        </PluginProperty>

        <div class="form-group form-check" v-show="!isCommon">
          <input
            type="checkbox"
            class="form-check-input"
            id="pluginEnable"
            :checked="settings.enable"
            @input="updateSettings"
            name="enable"
          />
          <label class="form-check-label" for="pluginEnable"
            >enable plugin</label
          >
        </div>
        <PluginProperty
          :id="'aquaServer'"
          :label="'Aqua Server'"
          :value="settings.AquaServer"
          :name="'AquaServer'"
          :description="'url of Aqua Server for links. E.g. https://myserver.aquasec.com'"
          :show="isCommon"
          :inputHandler="updateSettings"
        >
        </PluginProperty>
        <PluginProperty
          :id="'maxDbSize'"
          :label="'Max Db size'"
          :value="settings.Max_DB_Size"
          :name="'Max_DB_Size'"
          :description="'Max size of DB. MB. if empty then unlimited'"
          :show="isCommon"
          :inputHandler="updateSettings"
        >
        </PluginProperty>
        <PluginProperty
          :id="'deleteOldData'"
          :label="'Delete old data'"
          :value="settings.Delete_Old_Data"
          :name="'Delete Old Data'"
          :description="'delete data older than N day(s).  If empty then we do not delete.'"
          :show="isCommon"
          :inputHandler="updateSettings"
        >
        </PluginProperty>
        <PluginProperty
          :id="'dbVerifyInterval'"
          :label="'DB verify interval'"
          :value="settings.DbVerifyInterval"
          :name="'DbVerifyInterval'"
          :description="'hours. an Interval between tests of DB. Default: 1 hour'"
          :show="isCommon"
          :inputHandler="updateSettings"
        >
        </PluginProperty>

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
import PluginProperty from "./PluginProperty.vue";

const urlDescriptionByType = {
  splunk: "Mandatory. Url of a Splunk server",
  webhook: "Webhook's url",
  teams: "Webhook's url",
  jira: 'Mandatory. E.g "https://johndoe.atlassian.net"',
  slack: "",
};
const typesWithCredentials = ["serviceNow", "jira", "email"];

export default {
  data() {
    return {
      id: "",
    };
  },
  components: {
    PluginProperty,
  },
  computed: {
    ...mapState({
      settings(state) {
        const found = state.config.entries.filter(
          (item) => item.id === this.id
        );

        return found.length ? { ...found[0] } : { type: "email" };
      },
    }),
    showUrl() {
      return urlDescriptionByType[this.settings.type] !== undefined;
    },
    getUrlDescription() {
      return urlDescriptionByType[this.settings.type];
    },
    isCommon() {
      return this.settings.type === "common";
    },
    showCredentials() {
      return typesWithCredentials.indexOf(this.settings.type) >= 0;
    },
  },
  methods: {
    doSubmit() {
      if (this.id) {
        this.$store.commit("updateSettings", {
          value: this.settings,
          id: this.id,
        });
      } else {
        this.$store.commit("addSettings", this.settings);
      }
      this.$router.push({ name: "home" });
    },
    updateSettings(e) {
      const propName = e.target.attributes["name"].value;
      const inputType = e.target.attributes["type"].value;
      this.settings[propName] =
        inputType == "checkbox" ? e.target.checked : e.target.value;
    },
  },
  mounted() {
    this.id = this.$route.params.id;
  },
};
</script>