<template>
  <div>
    <div class="row justify-content-end pb-3 pr-3">
      <button id="submit" type="submit" class="btn btn-primary mr-2" @click="doSubmit">
        Submit
      </button>
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
          <PropertyField
            :id="'name'"
            :label="'Route Name'"
            :value="formValues.name"
            :errorMsg="errors['name']"
            :inputHandler="updateField"
            :validator="v(uniqueName)"
          />
          <div id="select-input-policies"> <h5>Input Policies</h5> </div>
          <b-form-group>
            <small class="form-text text-muted">
              Select rego policies to trigger the route
            </small>
            <div v-show="!custom_rule_enabled">
              <b-form-checkbox-group
                  id="rules"
                  v-model="formValues['input-files']"
                  :options="availableRegoRules"
                  name="rules"
                  stacked
              ></b-form-checkbox-group>
            </div>

            <br/>
            <b-form-checkbox
                  id="custom_rule"
                  v-model="custom_rule_enabled"
                  name="custom_rule"
                  value=true
                  button button-variant="primary"
                  size="sm"
              >Custom Rego Rule
            </b-form-checkbox>

          </b-form-group>

          <div v-if="custom_rule_enabled" class="form-group form-input">
            <codemirror
              :value="formValues.input"
              :options="cmOptions"
              id="input"
              name="input"
              @input="updateInput"
            >
            </codemirror>
            <small class="form-text text-muted">
              Set of REGO rules to filter received events. Leave empty to
              process all incoming events
            </small>
          </div>

          <h5>Actions</h5>
          <b-form-group>
            <small class="form-text text-muted">
              Select actions to perform when policy is triggered
            </small>
            <b-form-checkbox-group
              id="actions"
              v-model="formValues.actions"
              :options="availableActions"
              name="actions"
            ></b-form-checkbox-group>
          </b-form-group>

          <br/>
          <b-button v-b-toggle.plugins-collapse variant="primary" size="sm">Advanced Options</b-button>
          <div>
            <b-collapse id="plugins-collapse" class="mt-2">
            <b-card>
              Template
              <div class="form-group form-input">
                <small id="aHelp" class="form-text text-muted"
                >Select template to render events</small>
                <select
                    class="form-select form-control"
                    v-model="formValues.template"
                    id="template"
                    name="template"
                >
                  <option
                      v-for="template in availableTemplates"
                      v-bind:key="template"
                      :value="template"
                  >
                    {{ template }}
                  </option>
                </select>
              </div>
            </b-card>

              <b-card>
                <p class="card-text">
                <PropertyField
                    class="mb-4"
                    id="aggregateMessageNumber"
                    label="Aggregate-Message-Number"
                    :value="
                formValues.plugins
                  ? formValues.plugins['aggregate-message-number']
                  : undefined
              "
                    inputType="number"
                    name="aggregate-message-number"
                    description="Optional: Aggregate multiple messages into one ticket/message	Numeric number. Default is 1"
                    :inputHandler="updateRoutePluginField"
                />
                </p>
              </b-card>
              <b-card>
                <p class="card-text">
                  <PropertyField
                      class="mb-4"
                      id="aggregateMessageTimeout"
                      label="Aggregate-Message-Timeout"
                      :value="
                formValues.plugins
                  ? formValues.plugins['aggregate-message-timeout']
                  : undefined
              "
                      name="aggregate-message-timeout"
                      description="Optional: Aggregate multiple messages over period of time into one ticket/message	Xs (X number of seconds), Xm (X number of minutes), xH (X number of hours)"
                      :inputHandler="updateRoutePluginField"
                  />
                </p>
              </b-card>

              <b-card>
                <p class="card-text">
                  <PropertyField
                      class="mb-4"
                      id="uniqueMessageProps"
                      label="Unique Message Props"
                      name="unique-message-props"
                      :value="
                formValues.plugins && formValues.plugins['unique-message-props']
                  ? formValues.plugins['unique-message-props'].join(', ')
                  : undefined
              "
                      description="Optional: Comma separated list of top level properties which unique identify an event message. If message with same id is received more than once it will be ignored"
                      :inputHandler="updateRoutePluginCollectionField"
                  />
                </p>
              </b-card>

              <b-card>
                <p class="card-text">
                  <PropertyField
                      class="mb-4"
                      id="uniqueMessageTimeout"
                      label="Unique-Message-Timeout"
                      :value="
                formValues.plugins
                  ? formValues.plugins['unique-message-timeout']
                  : undefined
              "
                      name="unique-message-timeout"
                      description="Optional: Number of seconds/minutes/hours/days before expiring of a message. Expired messages are removed from db. If option is empty message is never deleted"
                      :inputHandler="updateRoutePluginField"
                  />
                </p>
              </b-card>

            </b-collapse>
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
import PropertyField from "./PropertyField.vue";

import { codemirror } from "vue-codemirror";

import "codemirror-rego/mode";
import "codemirror/lib/codemirror.css";

export default {
  data() {
    return {
      fields: {},
      errors: {},
      name: "",
      cmOptions: {
        tabSize: 4,
        mode: "rego",
        lineNumbers: true,
        line: true,
      },
      custom_rule_enabled: false,
    };
  },
  mixins: [FormFieldMixin, ValidationMixin],
  components: {
    PropertyField,
    codemirror,
  },
  computed: {
    ...mapState({
      formValues(state) {
        //required for mixins
        const found = state.routes.all.filter(
          (item) => item.name === this.name
        );

        const result = found.length ? { ...found[0] } : {};

        if (!result.action) {
          result.action = [];
        }

        return result;
      },
      availableActions(state) {
        return state.actions.all.map((item) => item.name);
      },
      availableTemplates(state) {
        return state.templates.all.map((item) => item.name);
      },
      availableRegoRules(state){
        return state.rules.all.map((item) => item.name);
      },
    }),
  },
  methods: {
    doSubmit() {
      if (!this.isFormValid()) {
        return;
      }

      if (this.name) {
        this.$store.dispatch("routes/update", {
          value: this.formValues,
          name: this.name,
        });
      } else {
        this.$store.dispatch("routes/add", this.formValues);
      }
      this.$router.push({ name: "routes" });
    },
    doRemove() {
      this.$store.dispatch("routes/remove", this.name);
      this.$router.push({ name: "routes" });
    },
    uniqueName(label, value) {
      if (!value) {
        return `${label} is required`;
      }
      const found = this.$store.state.routes.all.filter(
        (item) => item.name === value
      );

      if (found.length > 0 && found[0].name != this.name) {
        return `${value} is not unique`;
      }
      return false;
    },
    updateInput(v) {
      this.formValues.input = v;
    },
    updateRoutePluginField(e) {
      if (!this.formValues.plugins) {
        this.formValues.plugins = {};
      }
      const propName = e.target.attributes["name"].value;
      const inputType = e.target.attributes["type"]?.value;
      let v;
      switch (inputType) {
        case "checkbox": {
          v = e.target.checked;
          break;
        }
        case "number": {
          v = Number(e.target.value);
          break;
        }
        default: {
          v = e.target.value;
        }
      }
      this.formValues.plugins[propName] = v;
    },
    updateRoutePluginCollectionField(e) {
      if (!this.formValues.plugins) {
        this.formValues.plugins = {};
      }
      const propName = e.target.attributes["name"].value;
      const v = e.target.value.split(",").map((s) => s.trim());

      this.formValues.plugins[propName] = v;
    },
    custom_rule(){
      this.custom_rule_enabled = !this.custom_rule_enabled
    }
  },

  mounted() {
    this.name = this.$route.params.name;
  },
};
</script>
