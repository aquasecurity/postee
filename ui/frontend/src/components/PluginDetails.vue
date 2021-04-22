<template>
  <div class="card mt-4">
    <form @submit.prevent="doSubmit">
      <div class="card-header">
        <div class="d-flex">
          <div class="p-2 flex-grow-1">{{ settings.type }}</div>
          <button
            v-if="!!id"
            type="button"
            @click="doRemove"
            class="btn btn-link"
          >
            Remove
          </button>
        </div>
      </div>
      <div class="card-body">
        <div class="form-group form-input">
          <label for="pluginType">Type</label>
          <select
            class="form-select form-control"
            :value="settings.type"
            id="pluginType"
            name="type"
            @input="updateIntegrationType"
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
            >The integration type</small
          >
        </div>
        <PluginProperty
          :id="'name'"
          :label="'Name'"
          :value="settings.name"
          :errorMsg="errors['name']"
          :show="!isCommon"
          :inputHandler="updateSettings"
          :validator="v(required)"
        />
        <PluginCheckboxProperty
          :id="'enable'"
          :label="'Enable plugin'"
          :value="settings.enable"
          :show="!isCommon"
          :inputHandler="updateSettings"
        />
        <PluginProperty
          :id="'user'"
          :label="'User'"
          :value="settings.user"
          :name="'user'"
          :show="showCredentials"
          :inputHandler="updateSettings"
          :errorMsg="errors['user']"
          :validator="v(required)"
        />
        <PluginProperty
          :id="'password'"
          :label="'Password'"
          :inputType="'password'"
          :errorMsg="errors['password']"
          :value="settings.password"
          :name="'password'"
          :show="showCredentials"
          :inputHandler="updateSettings"
          :validator="v(required)"
        />
        <PluginProperty
          :id="'url'"
          :label="'Url'"
          :value="settings.url"
          :errorMsg="errors['url']"
          :name="'url'"
          :description="getUrlDescription"
          :show="showUrl"
          :inputHandler="updateSettings"
          :validator="v(url)"
        />

        <!-- common properties end-->
        <PluginProperty
          :id="'aquaServer'"
          :label="'Aqua Server'"
          :value="settings.AquaServer"
          :name="'AquaServer'"
          :description="'url of Aqua Server for links. E.g. https://myserver.aquasec.com'"
          :show="isCommon"
          :inputHandler="updateSettings"
        />
        <PluginProperty
          :id="'maxDbSize'"
          :label="'Max Db size'"
          :inputType="'number'"
          :value="settings.Max_DB_Size"
          :name="'Max_DB_Size'"
          :description="'Max size of DB. MB. if empty then unlimited'"
          :show="isCommon"
          :inputHandler="updateSettings"
        />
        <PluginProperty
          :id="'deleteOldData'"
          :label="'Delete old data'"
          :inputType="'number'"
          :value="settings.Delete_Old_Data"
          :name="'Delete Old Data'"
          :description="'delete data older than N day(s).  If empty then we do not delete.'"
          :show="isCommon"
          :inputHandler="updateSettings"
        />
        <PluginProperty
          :id="'dbVerifyInterval'"
          :label="'DB verify interval'"
          :inputType="'number'"
          :value="settings.DbVerifyInterval"
          :name="'DbVerifyInterval'"
          :description="'hours. an Interval between tests of DB. Default: 1 hour'"
          :show="isCommon"
          :inputHandler="updateSettings"
        />
        <!-- common properties end -->
        <!-- email custom properties start -->
        <PluginProperty
          :id="'host'"
          :label="'Host'"
          :errorMsg="errors['host']"
          :value="settings.host"
          :description="'Mandatory: SMTP host name (e.g. smtp.gmail.com)'"
          :show="isEmail"
          :inputHandler="updateSettings"
          :validator="v(required)"
        />
        <PluginProperty
          :id="'port'"
          :label="'Port'"
          :inputType="'number'"
          :errorMsg="errors['port']"
          :value="settings.port"
          :description="'Mandatory: SMTP server port (e.g. 587)'"
          :show="isEmail"
          :inputHandler="updateSettings"
          :validator="v(required)"
        />

        <PluginProperty
          :id="'sender'"
          :label="'Sender'"
          :value="settings.sender"
          :description="'The email address to use as a sender'"
          :errorMsg="errors['sender']"
          :show="isEmail"
          :inputHandler="updateSettings"
          :validator="v(email)"
        />

        <PluginProperty
          :id="'recipients'"
          :label="'Recipients'"
          :value="settings.recipients | toString"
          :description="'Mandatory: comma separated list of recipients'"
          :errorMsg="errors['recipients']"
          :show="isEmail"
          :inputHandler="updateCollection"
          :validator="v(recipients)"
        />

        <PluginCheckboxProperty
          :id="'useMX'"
          :label="'Use MX'"
          :value="settings.useMX"
          :show="isEmail"
          :inputHandler="updateSettings"
        />
        <!-- email custom properties end -->

        <!-- jira custom properties start -->
        <PluginProperty
          :id="'projectKey'"
          :label="'Project Key'"
          :name="'project_key'"
          :value="settings.project_key"
          :errorMsg="errors['project_key']"
          :description="'Mandatory. Specify the JIRA project key'"
          :show="isJira"
          :inputHandler="updateSettings"
          :validator="v(required)"
        />

        <PluginCheckboxProperty
          :id="'tlsVerify'"
          :label="'TLS verify'"
          :value="settings.tls_verify"
          :name="'tls_verify'"
          :show="isJira"
          :inputHandler="updateSettings"
        />

        <PluginProperty
          :id="'board'"
          :label="'Board'"
          :value="settings.board"
          :description="'Optional. Specify the Jira board name to open tickets on'"
          :show="isJira"
          :inputHandler="updateSettings"
        />

        <PluginProperty
          :id="'labels'"
          :label="'Labels'"
          :value="settings.labels | toString"
          :description="'Optional, specify array of labels to add to Ticket'"
          :show="isJira"
          :inputHandler="updateCollection"
        />
        <PluginProperty
          :id="'issuetype'"
          :label="'Issue Type'"
          :value="settings.issuetype"
          :description="'Optional. Specifty the issue type to open (Bug, Task, etc.). Default is Task'"
          :show="isJira"
          :inputHandler="updateSettings"
        />
        <PluginProperty
          :id="'priority'"
          :label="'Priority'"
          :value="settings.priority"
          :description="'Optional. Specify the issues severity. Default is High'"
          :show="isJira"
          :inputHandler="updateSettings"
        />
        <PluginProperty
          :id="'assignee'"
          :label="'Assignee'"
          :value="settings.assignee | toString"
          :description="jiraAssigneeDescription"
          :show="isJira"
          :inputHandler="updateCollection"
        />
        <!-- jira custom properties end -->
        <!-- serviceNow custom properties start -->
        <PluginProperty
          :id="'instance'"
          :label="'Instance'"
          :value="settings.instance"
          :description="'Mandatory. Name of ServiceNow  or Instance'"
          :errorMsg="errors['instance']"
          :show="isServiceNow"
          :inputHandler="updateSettings"
          :validator="v(required)"
        />
        <PluginProperty
          :id="'board'"
          :label="'Board'"
          :value="settings.board"
          :description="'Specify the ServiceNow board name to open tickets on. Default is incident'"
          :show="isServiceNow"
          :inputHandler="updateSettings"
        />
        <!-- serviceNow custom properties end -->
        <!-- splunk custom properties start -->
        <PluginProperty
          :id="'token'"
          :label="'Token'"
          :value="settings.token"
          :errorMsg="errors['token']"
          :description="'Mandatory. a HTTP Event Collector Token'"
          :show="isSplunk"
          :inputHandler="updateSettings"
          :validator="v(required)"
        />
        <PluginProperty
          :id="'sizeLimit'"
          :label="'Size Limit'"
          :value="settings.SizeLimit"
          :name="'SizeLimit'"
          :description="'Optional. Maximum scan length, in bytes. Default: 10000'"
          :show="isSplunk"
          :inputHandler="updateSettings"
        />
        <!-- splunk custom properties end -->

        <!-- general properties start -->

        <!--TODO make policyMinVulnerability a select-->
        <PluginProperty
          :id="'policyMinVulnerability'"
          :label="'Policy-Min-Vulnerability'"
          :value="settings['Policy-Min-Vulnerability']"
          :name="'Policy-Min-Vulnerability'"
          :description="generalProperties['Policy-Min-Vulnerability']"
          :show="showGeneralProperty('Policy-Min-Vulnerability')"
          :inputHandler="updateSettings"
        />

        <PluginProperty
          :id="'policyRegistry'"
          :label="'Policy-Registry'"
          :value="settings['Policy-Registry'] | toString"
          :name="'Policy-Registry'"
          :description="generalProperties['Policy-Registry']"
          :show="showGeneralProperty('Policy-Registry')"
          :inputHandler="updateCollection"
        />

        <PluginProperty
          :id="'policyImageName'"
          :label="'Policy-Image-Name'"
          :value="settings['Policy-Image-Name'] | toString"
          :name="'Policy-Image-Name'"
          :description="generalProperties['Policy-Image-Name']"
          :show="showGeneralProperty('Policy-Image-Name')"
          :inputHandler="updateCollection"
        />

        <PluginCheckboxProperty
          :id="'policyOnlyFixAvailable'"
          :label="'Policy-Only-Fix-Available'"
          :name="'Policy-Only-Fix-Available'"
          :value="settings['Policy-Only-Fix-Available']"
          :show="showGeneralProperty('Policy-Only-Fix-Available')"
          :description="generalProperties['Policy-Only-Fix-Available']"
          :inputHandler="updateSettings"
        />

        <PluginCheckboxProperty
          :id="'policyNonCompliant'"
          :label="'Policy-Non-Compliant'"
          :name="'Policy-Non-Compliant'"
          :value="settings['Policy-Non-Compliant']"
          :show="showGeneralProperty('Policy-Non-Compliant')"
          :description="generalProperties['Policy-Non-Compliant']"
          :inputHandler="updateSettings"
        />

        <PluginCheckboxProperty
          :id="'policyShowAll'"
          :label="'Policy-Show-All'"
          :name="'Policy-Show-All'"
          :value="settings['Policy-Show-All']"
          :show="showGeneralProperty('Policy-Show-All')"
          :description="generalProperties['Policy-Show-All']"
          :inputHandler="updateSettings"
        />

        <PluginProperty
          :id="'ignoreRegistry'"
          :label="'Ignore-Registry'"
          :value="settings['Ignore-Registry'] | toString"
          :name="'Ignore-Registry'"
          :description="generalProperties['Ignore-Registry']"
          :show="showGeneralProperty('Ignore-Registry')"
          :inputHandler="updateCollection"
        />

        <PluginProperty
          :id="'ignoreImageName'"
          :label="'Ignore-Image-Name'"
          :value="settings['Ignore-Image-Name'] | toString"
          :name="'Ignore-Image-Name'"
          :description="generalProperties['Ignore-Image-Name']"
          :show="showGeneralProperty('Ignore-Image-Name')"
          :inputHandler="updateCollection"
        >
        </PluginProperty>

        <PluginProperty
          :id="'aggregateIssuesNumber'"
          :label="'Aggregate-Issues-Number'"
          :value="settings['Aggregate-Issues-Number']"
          :inputType="'number'"
          :name="'Aggregate-Issues-Number'"
          :description="generalProperties['Aggregate-Issues-Number']"
          :show="showGeneralProperty('Aggregate-Issues-Number')"
          :inputHandler="updateSettings"
        />

        <PluginProperty
          :id="'aggregateIssuesTimeout'"
          :label="'Aggregate-Issues-Timeout'"
          :inputType="'number'"
          :value="settings['Aggregate-Issues-Timeout']"
          :name="'Aggregate-Issues-Timeout'"
          :description="generalProperties['Aggregate-Issues-Timeout']"
          :show="showGeneralProperty('Aggregate-Issues-Timeout')"
          :inputHandler="updateSettings"
        />

        <PluginProperty
          :id="'policyOPA'"
          :label="'Policy-OPA'"
          :value="settings['Policy-OPA'] | toString"
          :name="'Policy-OPA'"
          :description="generalProperties['Policy-OPA']"
          :show="showGeneralProperty('Policy-OPA')"
          :inputHandler="updateCollection"
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

        <div class="row form-group">
            <button type="submit" class="btn btn-primary mr-2">Submit</button>
            <button type="button" @click="doTest" class="btn btn-outline-primary mr-2">Test config</button>
            <b-spinner v-if="isTestingInProgress" variant="primary" label="Spinning"></b-spinner>
            <router-link :to="{ name: 'home' }" class="nav-link pl-1"
              >Cancel</router-link
            >
        </div>
      </div>
    </form>
  </div>
</template>
<script>
import { mapState } from "vuex";
import Validator from "./validator";
import PluginProperty from "./PluginProperty.vue";
import PluginCheckboxProperty from "./PluginCheckboxProperty.vue";
import generalProperties from "./general-properties";
import {ADD_SETTINGS_ACTION, UPDATE_SETTINGS_ACTION, REMOVE_SETTINGS_ACTION, TEST_ACTION} from "../store/store"

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
      id: "",
      addedControls: [],
      isTestingInProgress : false,
      fields: {},
      errors: {},
      generalProperties,
      selectedControl: "",
      integrationType: "", //stored separately to track dependencies
      jiraAssigneeDescription : 'Optional: comma separated list of users (emails) that will be assigned to ticket, e.g., ["john@yahoo.com"]. To assign a ticket to the Application Owner email address (as defined in Aqua Application Scope, owner email field), specify ["<%application_scope_owner%>"] as the assignee value'
    };
  },
  components: {
    PluginProperty,
    PluginCheckboxProperty,
  },
  computed: {
    ...mapState({
      settings(state) {
        const found = state.config.entries.filter(
          (item) => item.id === this.id
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
    isCommon() {
      return this.integrationType === "common";
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
      this.isTestingInProgress = true
      if (this.isFormValid()) {
          this.$store.dispatch(TEST_ACTION, this.settings).then(() => {
            this.$bvToast.toast('Integration is configured correctly', {
              title: 'Success',
              variant: 'success',
              autoHideDelay: 5000
          })
          this.isTestingInProgress = false
        }).catch((error) => {
          this.$bvToast.toast(error, {
            title: 'Connection error',
            variant: 'danger',
            autoHideDelay: 5000
          });
          this.isTestingInProgress = false
        });
      }
    },
    url(label, value) {
      if (!value) {
        return `${label} is required`;
      }

      const errorMsg = `Invalid url : ${value}`
      let url
      
      try {
        url = new URL(value);
      } catch (_) {
        return errorMsg;
      }

      return url.protocol === "http:" || url.protocol === "https:" ? false : errorMsg;
    },
    email(label, value) {
      const re = /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/
      return re.test(String(value).toLowerCase())? false : `Invalid email '${value}'`
    },
    required(label, value) {
      return !value ? `${label} is required`: false;
    },
    recipients(label, value) {
      const hasOneElement = value && value.length && value[0]
      if (!hasOneElement) {
        return `At least one of ${label} is required`
      } else {
        for (const email of value) {
          const v = this.email("-", email);
          if (v) {
            return v;
          }
        }
      }
      return  false
    },
    showGeneralProperty(generalPropertyName) {
      const hasOwnProperty = Object.prototype.hasOwnProperty.call(
        this.settings,
        generalPropertyName
      );
      return (
        hasOwnProperty || this.addedControls.indexOf(generalPropertyName) >= 0
      );
    },
    v(validationFn) {
      return new Validator(this.fields, validationFn);
    },
    isFormValid() {
      const fields = this.fields;
      let invalid = false;
      let firstElement
      this.errors = {}

      for (const id in fields) {
        const validator = fields[id]
        const validationFn= validator.validationFn
        const element = document.getElementById(id)

      if (element) { //only elements in DOM are validated
          const r = validationFn(validator.label, this.settings[validator.name])
          if (r) {
            this.errors[validator.name] = r
            if (firstElement === undefined) {
              firstElement = element
            }
            invalid = true
          }
        }
      }

      if (invalid) {
        firstElement.focus();
      }

      return !invalid
    },
    doSubmit() {
      if (!this.isFormValid()) {
        return
      }
      if (this.id) {
        this.$store.dispatch(UPDATE_SETTINGS_ACTION, {
          value: this.settings,
          id: this.id,
        });
      } else {
        this.$store.dispatch(ADD_SETTINGS_ACTION, this.settings);
      }
      this.$router.push({ name: "home" });
    },
    updateIntegrationType(e) {
      this.integrationType = e.target.value;
      this.updateSettings(e);
    },
    updateSettings(e) {
      const propName = e.target.attributes["name"].value;
      const inputType = e.target.attributes["type"]?.value;
      this.settings[propName] =
        inputType == "checkbox" ? e.target.checked : e.target.value;
    },
    updateCollection(e) {
      const propName = e.target.attributes["name"].value;
      const v = e.target.value.split(",").map((s) => s.trim());

      this.settings[propName] = v;
    },
    updateSelectedControl(e) {
      this.selectedControl = e.target.value;
    },
    selectControl() {
      this.addedControls.push(this.selectedControl);
    },
    doRemove() {
      this.$store.dispatch(REMOVE_SETTINGS_ACTION, this.id);
      this.$router.push({ name: "home" });
    },
  },
  mounted() {
    this.id = this.$route.params.id;
  },
};
</script>