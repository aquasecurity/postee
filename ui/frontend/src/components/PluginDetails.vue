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
            :id="'name'"
            :label="'Name'"
            :value="formValues.name"
            :errorMsg="errors['name']"
            :inputHandler="updateField"
            :validator="v(required)"
          />
          <PluginCheckboxProperty
            :id="'enable'"
            :label="'Enable plugin'"
            :value="formValues.enable"
            :inputHandler="updateField"
          />
          <PluginProperty
            :id="'user'"
            :label="'User'"
            :value="formValues.user"
            :name="'user'"
            :show="showCredentials"
            :inputHandler="updateField"
            :errorMsg="errors['user']"
            :validator="v(required)"
          />
          <PluginProperty
            :id="'password'"
            :label="'Password'"
            :inputType="'password'"
            :errorMsg="errors['password']"
            :value="formValues.password"
            :name="'password'"
            :show="showCredentials"
            :inputHandler="updateField"
            :validator="v(required)"
          />
          <PluginProperty
            :id="'url'"
            :label="'Url'"
            :value="formValues.url"
            :errorMsg="errors['url']"
            :name="'url'"
            :description="getUrlDescription"
            :show="showUrl"
            :inputHandler="updateField"
            :validator="v(url)"
          />

          <!-- email custom properties start -->
          <PluginProperty
            :id="'host'"
            :label="'Host'"
            :errorMsg="errors['host']"
            :value="formValues.host"
            :description="'Mandatory: SMTP host name (e.g. smtp.gmail.com)'"
            :show="isEmail"
            :inputHandler="updateField"
            :validator="v(required)"
          />
          <PluginProperty
            :id="'port'"
            :label="'Port'"
            :inputType="'number'"
            :errorMsg="errors['port']"
            :value="formValues.port"
            :description="'Mandatory: SMTP server port (e.g. 587)'"
            :show="isEmail"
            :inputHandler="updateField"
            :validator="v(required)"
          />

          <PluginProperty
            :id="'sender'"
            :label="'Sender'"
            :value="formValues.sender"
            :description="'The email address to use as a sender'"
            :errorMsg="errors['sender']"
            :show="isEmail"
            :inputHandler="updateField"
            :validator="v(email)"
          />

          <PluginProperty
            :id="'recipients'"
            :label="'Recipients'"
            :value="formValues.recipients | toString"
            :description="'Mandatory: comma separated list of recipients'"
            :errorMsg="errors['recipients']"
            :show="isEmail"
            :inputHandler="updateCollectionField"
            :validator="v(recipients)"
          />

          <PluginCheckboxProperty
            :id="'useMX'"
            :label="'Use MX'"
            :value="formValues.useMX"
            :show="isEmail"
            :inputHandler="updateField"
          />
          <!-- email custom properties end -->

          <!-- jira custom properties start -->
          <PluginProperty
            :id="'projectKey'"
            :label="'Project Key'"
            :name="'project_key'"
            :value="formValues.project_key"
            :errorMsg="errors['project_key']"
            :description="'Mandatory. Specify the JIRA project key'"
            :show="isJira"
            :inputHandler="updateField"
            :validator="v(required)"
          />

          <PluginCheckboxProperty
            :id="'tlsVerify'"
            :label="'TLS verify'"
            :value="formValues.tls_verify"
            :name="'tls_verify'"
            :show="isJira"
            :inputHandler="updateField"
          />

          <PluginProperty
            :id="'board'"
            :label="'Board'"
            :value="formValues.board"
            :description="'Optional. Specify the Jira board name to open tickets on'"
            :show="isJira"
            :inputHandler="updateField"
          />

          <PluginProperty
            :id="'labels'"
            :label="'Labels'"
            :value="formValues.labels | toString"
            :description="'Optional, specify array of labels to add to Ticket'"
            :show="isJira"
            :inputHandler="updateCollectionField"
          />
          <PluginProperty
            :id="'issuetype'"
            :label="'Issue Type'"
            :value="formValues.issuetype"
            :description="'Optional. Specifty the issue type to open (Bug, Task, etc.). Default is Task'"
            :show="isJira"
            :inputHandler="updateField"
          />
          <PluginProperty
            :id="'priority'"
            :label="'Priority'"
            :value="formValues.priority"
            :description="'Optional. Specify the issues severity. Default is High'"
            :show="isJira"
            :inputHandler="updateField"
          />
          <PluginProperty
            :id="'assignee'"
            :label="'Assignee'"
            :value="formValues.assignee | toString"
            :description="jiraAssigneeDescription"
            :show="isJira"
            :inputHandler="updateCollectionField"
          />
          <!-- jira custom properties end -->
          <!-- serviceNow custom properties start -->
          <PluginProperty
            :id="'instance'"
            :label="'Instance'"
            :value="formValues.instance"
            :description="'Mandatory. Name of ServiceNow  or Instance'"
            :errorMsg="errors['instance']"
            :show="isServiceNow"
            :inputHandler="updateField"
            :validator="v(required)"
          />
          <PluginProperty
            :id="'board'"
            :label="'Board'"
            :value="formValues.board"
            :description="'Specify the ServiceNow board name to open tickets on. Default is incident'"
            :show="isServiceNow"
            :inputHandler="updateField"
          />
          <!-- serviceNow custom properties end -->
          <!-- splunk custom properties start -->
          <PluginProperty
            :id="'token'"
            :label="'Token'"
            :value="formValues.token"
            :errorMsg="errors['token']"
            :description="'Mandatory. a HTTP Event Collector Token'"
            :show="isSplunk"
            :inputHandler="updateField"
            :validator="v(required)"
          />
          <PluginProperty
            :id="'sizeLimit'"
            :label="'Size Limit'"
            :value="formValues.SizeLimit"
            :name="'SizeLimit'"
            :description="'Optional. Maximum scan length, in bytes. Default: 10000'"
            :show="isSplunk"
            :inputHandler="updateField"
          />
          <!-- splunk custom properties end -->

          <!-- general properties start -->

          <!--TODO make policyMinVulnerability a select-->
          <PluginProperty
            :id="'policyMinVulnerability'"
            :label="'Policy-Min-Vulnerability'"
            :value="formValues['Policy-Min-Vulnerability']"
            :name="'Policy-Min-Vulnerability'"
            :description="generalProperties['Policy-Min-Vulnerability']"
            :show="showGeneralProperty('Policy-Min-Vulnerability')"
            :inputHandler="updateField"
          />

          <PluginProperty
            :id="'policyRegistry'"
            :label="'Policy-Registry'"
            :value="formValues['Policy-Registry'] | toString"
            :name="'Policy-Registry'"
            :description="generalProperties['Policy-Registry']"
            :show="showGeneralProperty('Policy-Registry')"
            :inputHandler="updateCollectionField"
          />

          <PluginProperty
            :id="'policyImageName'"
            :label="'Policy-Image-Name'"
            :value="formValues['Policy-Image-Name'] | toString"
            :name="'Policy-Image-Name'"
            :description="generalProperties['Policy-Image-Name']"
            :show="showGeneralProperty('Policy-Image-Name')"
            :inputHandler="updateCollectionField"
          />

          <PluginCheckboxProperty
            :id="'policyOnlyFixAvailable'"
            :label="'Policy-Only-Fix-Available'"
            :name="'Policy-Only-Fix-Available'"
            :value="formValues['Policy-Only-Fix-Available']"
            :show="showGeneralProperty('Policy-Only-Fix-Available')"
            :description="generalProperties['Policy-Only-Fix-Available']"
            :inputHandler="updateField"
          />

          <PluginCheckboxProperty
            :id="'policyNonCompliant'"
            :label="'Policy-Non-Compliant'"
            :name="'Policy-Non-Compliant'"
            :value="formValues['Policy-Non-Compliant']"
            :show="showGeneralProperty('Policy-Non-Compliant')"
            :description="generalProperties['Policy-Non-Compliant']"
            :inputHandler="updateField"
          />

          <PluginCheckboxProperty
            :id="'policyShowAll'"
            :label="'Policy-Show-All'"
            :name="'Policy-Show-All'"
            :value="formValues['Policy-Show-All']"
            :show="showGeneralProperty('Policy-Show-All')"
            :description="generalProperties['Policy-Show-All']"
            :inputHandler="updateField"
          />

          <PluginProperty
            :id="'ignoreRegistry'"
            :label="'Ignore-Registry'"
            :value="formValues['Ignore-Registry'] | toString"
            :name="'Ignore-Registry'"
            :description="generalProperties['Ignore-Registry']"
            :show="showGeneralProperty('Ignore-Registry')"
            :inputHandler="updateCollectionField"
          />

          <PluginProperty
            :id="'ignoreImageName'"
            :label="'Ignore-Image-Name'"
            :value="formValues['Ignore-Image-Name'] | toString"
            :name="'Ignore-Image-Name'"
            :description="generalProperties['Ignore-Image-Name']"
            :show="showGeneralProperty('Ignore-Image-Name')"
            :inputHandler="updateCollectionField"
          >
          </PluginProperty>

          <PluginProperty
            :id="'aggregateIssuesNumber'"
            :label="'Aggregate-Issues-Number'"
            :value="formValues['Aggregate-Issues-Number']"
            :inputType="'number'"
            :name="'Aggregate-Issues-Number'"
            :description="generalProperties['Aggregate-Issues-Number']"
            :show="showGeneralProperty('Aggregate-Issues-Number')"
            :inputHandler="updateField"
          />

          <PluginProperty
            :id="'aggregateIssuesTimeout'"
            :label="'Aggregate-Issues-Timeout'"
            :inputType="'number'"
            :value="formValues['Aggregate-Issues-Timeout']"
            :name="'Aggregate-Issues-Timeout'"
            :description="generalProperties['Aggregate-Issues-Timeout']"
            :show="showGeneralProperty('Aggregate-Issues-Timeout')"
            :inputHandler="updateField"
          />

          <PluginProperty
            :id="'policyOPA'"
            :label="'Policy-OPA'"
            :value="formValues['Policy-OPA'] | toString"
            :name="'Policy-OPA'"
            :description="generalProperties['Policy-OPA']"
            :show="showGeneralProperty('Policy-OPA')"
            :inputHandler="updateCollectionField"
          />

          <!--  general properties end -->
          <div class="row form-group">
            <div class="col-md-6">
              <select
                class="form-select form-control p-2 w-100"
                :value="selectedControl"
                id="optionalControlSelector"
                @input="updateSelectedControl"
              >
                <option
                  v-for="(desc, key) in generalProperties"
                  :key="key"
                  :value="key"
                >
                  {{ key }}
                </option>
              </select>
            </div>

            <div class="col-md-6">
              <button
                type="button"
                @click="selectControl"
                class="btn btn-primary"
              >
                Add Control
              </button>
            </div>
            <div class="col-12 p-2">
              <small
                id="generalProperyDescription"
                class="form-text text-muted"
                >{{ generalProperties[selectedControl] }}</small
              >
            </div>
          </div>
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
import generalProperties from "./general-properties";
import {
  ADD_OUTPUT_ACTION,
  UPDATE_OUTPUT_ACTION,
  REMOVE_OUTPUT_ACTION,
  TEST_ACTION,
} from "../store/store";

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
      addedControls: [],
      isTestingInProgress: false,
      fields: {}, //required for mixins
      errors: {}, //required for mixins
      generalProperties,
      selectedControl: "",
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
        const found = state.config.outputs.filter(
          (item) => item.name === this.name
        );

        const result = found.length ? { ...found[0] } : { type: "email" };

        this.integrationType = result.type;

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
        .dispatch(TEST_ACTION, this.formValues)
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
    showGeneralProperty(generalPropertyName) {
      const hasOwnProperty = Object.prototype.hasOwnProperty.call(
        this.formValues,
        generalPropertyName
      );
      return (
        hasOwnProperty || this.addedControls.indexOf(generalPropertyName) >= 0
      );
    },
    doSubmit() {
      if (!this.isFormValid()) {
        return;
      }
      if (this.name) {
        this.$store.dispatch(UPDATE_OUTPUT_ACTION, {
          value: this.formValues,
          name: this.name,
        });
      } else {
        this.$store.dispatch(ADD_OUTPUT_ACTION, this.formValues);
      }
      this.$router.push({ name: "home" });
    },
    updateIntegrationType(e) {
      this.integrationType = e.target.value;
      this.updateField(e);
    },
    updateSelectedControl(e) {
      this.selectedControl = e.target.value;
    },
    selectControl() {
      this.addedControls.push(this.selectedControl);
    },
    doRemove() {
      this.$store.dispatch(REMOVE_OUTPUT_ACTION, this.name);
      this.$router.push({ name: "home" });
    },
  },
  mounted() {
    this.name = this.$route.params.name;
  },
};
</script>