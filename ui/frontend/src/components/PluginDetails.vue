<template>
  <div>
    <div class="row justify-content-end pb-3 pr-3">
      <button type="submit" class="btn btn-primary mr-2" @click="doSubmit">
        Submit
      </button>
      <button
        type="button"
        @click="doTest"
        class="btn btn-outline-primary mr-2"
      >
        Test config
      </button>
      <b-spinner
        v-if="isTestingInProgress"
        variant="primary"
        label="Spinning"
        class="mr-2"
      ></b-spinner>
      <button
        v-if="!!name"
        type="button"
        @click="doRemove"
        class="btn btn-outline-primary"
      >
        Remove
      </button>
    </div>
    <div class="card">
      <form @submit.prevent="doSubmit">
        <div class="card-body">
          <div class="form-group form-input">
            <label for="pluginType">Type</label>
            <select
              class="form-select form-control"
              :value="formValues.type"
              id="pluginType"
              name="type"
              @input="updateIntegrationType"
            >
              <option value="email">Email</option>
              <option value="jira">Jira</option>
              <option value="slack">Slack</option>
              <option value="teams">Teams</option>
              <option value="webhook">Webhook</option>
              <option value="splunk">Splunk</option>
              <option value="serviceNow">ServiceNow</option>
            </select>
            <small id="aHelp" class="form-text text-muted"
              >The integration type</small
            >
          </div>
          <PluginProperty
            id="name"
            label="Name"
            :value="formValues.name"
            :errorMsg="errors['name']"
            :inputHandler="updateField"
            :validator="v(uniqueName)"
          />
          <!-- enable is not required here-->
          <PluginCheckboxProperty
            id="enable"
            label="Enable plugin"
            :value="formValues.enable"
            :inputHandler="updateField"
          />
          <PluginProperty
            id="user"
            label="User"
            :value="formValues.user"
            name="user"
            :show="showCredentials"
            :inputHandler="updateField"
            :errorMsg="errors['user']"
            :validator="v(required)"
          />
          <PluginProperty
            id="password"
            label="Password"
            inputType="password"
            :errorMsg="errors['password']"
            :value="formValues.password"
            name="password"
            :show="showCredentials"
            :inputHandler="updateField"
            :validator="v(required)"
          />
          <PluginProperty
            id="url"
            label="Url"
            :value="formValues.url"
            :errorMsg="errors['url']"
            name="url"
            :description="getUrlDescription"
            :show="showUrl"
            :inputHandler="updateField"
            :validator="v(url)"
          />

          <!-- email custom properties start -->
          <PluginProperty
            id="host"
            label="Host"
            :errorMsg="errors['host']"
            :value="formValues.host"
            description="Mandatory: SMTP host name (e.g. smtp.gmail.com)"
            :show="isEmail"
            :inputHandler="updateField"
            :validator="v(required)"
          />
          <PluginProperty
            id="port"
            label="Port"
            inputType="number"
            :errorMsg="errors['port']"
            :value="formValues.port"
            description="Mandatory: SMTP server port (e.g. 587)"
            :show="isEmail"
            :inputHandler="updateField"
            :validator="v(required)"
          />

          <PluginProperty
            id="sender"
            label="Sender"
            :value="formValues.sender"
            description="The email address to use as a sender"
            :errorMsg="errors['sender']"
            :show="isEmail"
            :inputHandler="updateField"
            :validator="v(email)"
          />

          <PluginProperty
            id="recipients"
            label="Recipients"
            :value="formValues.recipients | toString"
            description="Mandatory: comma separated list of recipients"
            :errorMsg="errors['recipients']"
            :show="isEmail"
            :inputHandler="updateCollectionField"
            :validator="v(recipients)"
          />

          <PluginCheckboxProperty
            id="useMX"
            label="Use MX"
            :value="formValues.useMX"
            :show="isEmail"
            :inputHandler="updateField"
          />
          <!-- email custom properties end -->

          <!-- jira custom properties start -->
          <PluginProperty
            id="projectKey"
            label="Project Key"
            name="project_key"
            :value="formValues.project_key"
            :errorMsg="errors['project_key']"
            :description="'Mandatory. Specify the JIRA project key'"
            :show="isJira"
            :inputHandler="updateField"
            :validator="v(required)"
          />

          <PluginCheckboxProperty
            id="tlsVerify"
            label="TLS verify"
            :value="formValues.tls_verify"
            name="tls_verify"
            :show="isJira"
            :inputHandler="updateField"
          />

          <PluginProperty
            id="board"
            label="Board"
            :value="formValues.board"
            description="Optional. Specify the Jira board name to open tickets on"
            :show="isJira"
            :inputHandler="updateField"
          />

          <PluginProperty
            id="fixVersions"
            label="Fix Versions"
            :value="formValues.fixVersions | toString"
            description="Optional, specify comma separated list of Fix versions to add to Ticket"
            :show="isJira"
            :inputHandler="updateCollectionField"
          />
          <PluginProperty
            id="affectsVersions"
            label="Affects Versions"
            :value="formValues.affectsVersions | toString"
            description="Optional, specify comma separated list of Affects versions to add to Ticket"
            :show="isJira"
            :inputHandler="updateCollectionField"
          />

          <PluginProperty
            id="labels"
            label="Labels"
            :value="formValues.labels | toString"
            description="Optional, specify comma separated list of labels to add to Ticket"
            :show="isJira"
            :inputHandler="updateCollectionField"
          />
          <PluginProperty
            id="issuetype"
            label="Issue Type"
            :value="formValues.issuetype"
            description="Optional. Specify the issue type to open (Bug, Task, etc.). Default is Task"
            :show="isJira"
            :inputHandler="updateField"
          />
          <PluginProperty
            id="priority"
            label="Priority"
            :value="formValues.priority"
            description="Optional. Specify the issues severity. Default is High"
            :show="isJira"
            :inputHandler="updateField"
          />
          <PluginProperty
            id="assignee"
            label="Assignee"
            :value="formValues.assignee | toString"
            :description="jiraAssigneeDescription"
            :show="isJira"
            :inputHandler="updateCollectionField"
          />
          <PluginProperty
            id="sprint"
            label="Sprint"
            :value="formValues.sprint"
            description="Optional Sprint name, e.g., '3.5 Sprint 8'"
            :show="isJira"
            :inputHandler="updateField"
          />
          <h5 v-show="isJira">Jira custom fields</h5>

          <b-row class="form-group" v-for="(cfValue, cfName) in unknowns" v-bind:key="cfName" :show="isJira">
            <b-col sm="2">
              <label :for="'cf-' + cfName">{{cfName}}</label>
            </b-col>
            <b-col sm="9">
              <b-form-input :id="'cf-' + cfName" :name="cfName" v-model="unknowns[cfName]"></b-form-input>
            </b-col>
            <b-col sm="1" class="pr-2">
              <b-button variant="primary" @click="removeCf(cfName)" ><span aria-hidden="true">&times;</span></b-button>
            </b-col>
          </b-row>

          <div class="form-group mt-3 row" v-show="isJira">
            <b-form-input
              id="cf-adder"
              v-model="addedControl"
              class="col-sm-3 mr-2 ml-2"
              type="text"
              placeholder="Add new custom field"
            ></b-form-input>
            <b-button variant="primary" @click="addCf">Add</b-button>
          </div>

          <!-- jira custom properties end -->
          <!-- serviceNow custom properties start -->
          <PluginProperty
            id="instance"
            label="Instance"
            :value="formValues.instance"
            description="Mandatory. Name of ServiceNow  or Instance"
            :errorMsg="errors['instance']"
            :show="isServiceNow"
            :inputHandler="updateField"
            :validator="v(required)"
          />
          <PluginProperty
            id="board"
            label="Board"
            :value="formValues.board"
            description="Specify the ServiceNow board name to open tickets on. Default is incident"
            :show="isServiceNow"
            :inputHandler="updateField"
          />
          <!-- serviceNow custom properties end -->
          <!-- splunk custom properties start -->
          <PluginProperty
            id="token"
            label="Token"
            :value="formValues.token"
            :errorMsg="errors['token']"
            description="Mandatory. a HTTP Event Collector Token"
            :show="isSplunk"
            :inputHandler="updateField"
            :validator="v(required)"
          />
          <PluginProperty
            id="sizeLimit"
            label="Size Limit"
            :value="formValues.SizeLimit"
            inputType="number"
            :name="'SizeLimit'"
            description="Optional. Maximum scan length, in bytes. Default: 10000"
            :show="isSplunk"
            :inputHandler="updateField"
          />
          <!-- splunk custom properties end -->
        </div>
      </form>
    </div>
  </div>
</template>
<script>

import { mapState } from "vuex";
import ValidationMixin from "./validator";
import FormFieldMixin from "./form";
import PluginProperty from "./PluginProperty.vue";
import PluginCheckboxProperty from "./PluginCheckboxProperty.vue";

const urlDescriptionByType = {
  splunk: "Mandatory. Url of a Splunk server",
  webhook: "Webhook's url",
  teams: "Webhook's url",
  jira: 'Mandatory. E.g "https://johndoe.atlassian.net"',
  slack: "",
};
const typesWithCredentials = ["serviceNow", "jira", "email"]; //TODO add description strings

export default {
  data() {
    return {
      name: "",
      addedControl: "",
      unknowns: [],
      isTestingInProgress: false,
      fields: {}, //required for mixins
      errors: {}, //required for mixins
      integrationType: "", //stored separately to track dependencies
      jiraAssigneeDescription:
        'Optional: comma separated list of users (emails) that will be assigned to ticket, e.g., ["john@yahoo.com"]. To assign a ticket to the Application Owner email address (as defined in Aqua Application Scope, owner email field), specify ["<%application_scope_owner%>"] as the assignee value',
    };
  },
  mixins: [FormFieldMixin, ValidationMixin],
  components: {
    PluginProperty,
    PluginCheckboxProperty,
  },
  computed: {
    ...mapState({
      formValues(state) { //required for mixins
        const found = state.outputs.all.filter(
          (item) => item.name === this.name
        );

        const result = found.length ? { ...found[0] } : { type: "email" };

        this.integrationType = result.type;
        this.unknowns = {...result.unknowns}

        return result;
      },
    }),
    showUrl() {
      return urlDescriptionByType[this.integrationType] !== undefined;
    },
    getUrlDescription() {
      return urlDescriptionByType[this.integrationType];
    },
    isServiceNow() {
      return this.integrationType === "serviceNow";
    },
    isSplunk() {
      return this.integrationType === "splunk";
    },
    isEmail() {
      return this.integrationType === "email";
    },
    isJira() {
      return this.integrationType === "jira";
    },
    showCredentials() {
      return typesWithCredentials.indexOf(this.integrationType) >= 0;
    },
  },
  filters: {
    toString(col) {
      return col ? col.join(", ") : undefined;
    },
  },
  methods: {
    doTest() {
      this.isTestingInProgress = true;

      if (!this.isFormValid()) {
        return;
      }

      this.$store
        .dispatch("outputs/test", this.formValues)
        .then(() => {
          this.$bvToast.toast("Integration is configured correctly", {
            title: "Success",
            variant: "success",
            autoHideDelay: 5000,
          });
          this.isTestingInProgress = false;
        })
        .catch((error) => {
          this.$bvToast.toast(error, {
            title: "Connection error",
            variant: "danger",
            autoHideDelay: 15000,
          });
          this.isTestingInProgress = false;
        });
    },
    doSubmit() {
      if (!this.isFormValid()) {
        return;
      }
      //apply unknowns
      if (Object.keys(this.unknowns).length > 0) {
        this.formValues.unknowns={...this.unknowns}
      }
      if (this.name) {
        this.$store.dispatch("outputs/update", {
          value: this.formValues,
          name: this.name,
        });
      } else {
        this.$store.dispatch("outputs/add", this.formValues);
      }
      this.$router.push({ name: "home" });
    },
    updateIntegrationType(e) {
      this.integrationType = e.target.value;
      this.updateField(e);
    },
    doRemove() {
      this.$store.dispatch("outputs/remove", this.name);
      this.$router.push({ name: "home" });
    },
    uniqueName(label, value) {
      if  (!value) {
        return `${label} is required`
      }
      const found = this.$store.state.outputs.all.filter(
        (item) => item.name === value
      );

      if (found.length > 0 && found[0].name != this.name) {
        return `${value} is not unique`
      }
      return false
    },
    addCf() {
      const unknowns = {...this.unknowns}
      unknowns[this.addedControl] = ""
      this.addedControl = ""
      this.unknowns = {...unknowns}
    },
    removeCf(propertyName) {
      const unknowns = {...this.unknowns}
      delete unknowns[propertyName]
      this.unknowns = {...unknowns}
    }

  },
  mounted() {
    this.name = this.$route.params.name;
  },
};
</script>