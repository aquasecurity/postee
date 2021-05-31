<template>
  <div>
    <div class="row justify-content-end pb-3 pr-3">
      <button type="submit" class="btn btn-primary mr-2" @click="doSubmit">
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
            :label="'Name'"
            :value="formValues.name"
            :errorMsg="errors['name']"
            :inputHandler="updateField"
            :validator="v(uniqueName)"
          />
          <div class="form-group form-input">
            <label class="form-label" for="input">REGO rule:</label>

            <codemirror
              :value="formValues.input"
              :options="cmOptions"
              id="input"
              name="input"
              @input="updateInput"
            >
            </codemirror>
            <small class="form-text text-muted">
              Set of REGO rules to filter received events
            </small>
          </div>

          <b-form-group label="Selected outputs">
            <b-form-checkbox-group
              id="outputs"
              v-model="formValues.outputs"
              :options="availableOutputs"
              name="outputs"
            ></b-form-checkbox-group>
            <small class="form-text text-muted">
              Select outputs to route events to
            </small>
          </b-form-group>


          <div class="form-group form-input">
            <label for="template">Template</label>
            <select
              class="form-select form-control"
              v-model="formValues.template"
              id="template"
              name="template"
            >
              <option v-for="template in availableTemplates" v-bind:key="template" :value="template">{{template}}</option>
            </select>
            <small id="aHelp" class="form-text text-muted"
              >Select templates to render events</small
            >
          </div>

          <div class="row">
            <div class="col">
              <PropertyField
                id="aggregateIssuesNumber"
                label="Aggregate-Issues-Number"
                :value="formValues.plugins?formValues.plugins['Aggregate-Issues-Number']:undefined"
                inputType="number"
                name="Aggregate-Issues-Number"
                description="Optional: Aggregate multiple scans into one ticket/message	Numeric number. Default is 1"
                :inputHandler="updateRoutePluginField"
              />
            </div>
            <div class="col">
              <PropertyField
                id="aggregateIssuesTimeout"
                label="Aggregate-Issues-Timeout"
                :value="formValues.plugins?formValues.plugins['Aggregate-Issues-Timeout']:undefined"
                name="Aggregate-Issues-Timeout"
                description="Optional: Aggregate multiple scans over period of time into one ticket/message	Xs (X number of seconds), Xm (X number of minutes), xH (X number of hours)"
                :inputHandler="updateRoutePluginField"
              />
            </div>
          </div>
          <CheckboxPropertyField
            id="policyShowAll"
            label="Policy-Show-All"
            name="Policy-Show-All"
            :value="formValues.plugins?formValues.plugins['Policy-Show-All']:undefined"
            description="Optional: trigger the output for all scan results. If set to true, output will be triggered even for old scan results. Default value: false"
            :inputHandler="updateRoutePluginField"
          />
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
import CheckboxPropertyField from "./CheckboxPropertyField.vue";

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
    };
  },
  mixins: [FormFieldMixin, ValidationMixin],
  components: {
    PropertyField,
    CheckboxPropertyField,
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

        if (!result.output) {
          result.output = [];
        }

        return result;
      },
      availableOutputs(state) {
        return state.outputs.all.map((item) => item.name);
      },
      availableTemplates(state) {
        return state.templates.all.map((item) => item.name);
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
        this.formValues.plugins = {}
      }
      const propName = e.target.attributes["name"].value;
      const inputType = e.target.attributes["type"]?.value;
      let v
      switch(inputType) {
          case "checkbox": {
              v = e.target.checked
              break;
          }
          case "number": {
              v = Number(e.target.value)
              break;
          }
          default: {
              v = e.target.value
          }

      }
      this.formValues.plugins[propName] = v;
    }
  },
  mounted() {
    this.name = this.$route.params.name;
  },
};
</script>
