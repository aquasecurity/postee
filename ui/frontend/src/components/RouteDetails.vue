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
          <PluginProperty
            :id="'name'"
            :label="'Name'"
            :value="formValues.name"
            :errorMsg="errors['name']"
            :inputHandler="updateField"
            :validator="v(uniqueName)"
          />
          <div class="form-group form-input">
            <label class="form-label" for="input">REGO rule:</label>

            <!-- TODO add code mirror support -->
            <textarea
              :value="formValues.input"
              id="input"
              placeholder="add REGO rule"
              name="input"
              @input="updateField"
              class="form-control"
              rows="3"
              v-bind:class="{ 'is-invalid': errors.input }"
            ></textarea>
            <small class="form-text text-muted">
              Set of REGO rules to filter received events
            </small>
            <div class="form-text invalid-feedback">{{ errors.input }}</div>
          </div>

          <b-form-group label="Selected outputs">
            <b-form-checkbox-group
              id="output"
              v-model="formValues.output"
              :options="availableOutputs"
              name="output"
            ></b-form-checkbox-group>
            <small class="form-text text-muted">
              Select outputs to route events to
            </small>
          </b-form-group>

          <PluginProperty
            :id="'aggregateIssuesNumber'"
            :label="'Aggregate-Issues-Number'"
            :value="formValues['Aggregate-Issues-Number']"
            :inputType="'number'"
            :name="'Aggregate-Issues-Number'"
            description="Optional: Aggregate multiple scans into one ticket/message	Numeric number. Default is 1"
            :inputHandler="updateField"
          />

          <PluginProperty
            :id="'aggregateIssuesTimeout'"
            :label="'Aggregate-Issues-Timeout'"
            :inputType="'number'"
            :value="formValues['Aggregate-Issues-Timeout']"
            :name="'Aggregate-Issues-Timeout'"
            description="Optional: Aggregate multiple scans over period of time into one ticket/message	Xs (X number of seconds), Xm (X number of minutes), xH (X number of hours)"
            :inputHandler="updateField"
          />
          <PluginCheckboxProperty
            :id="'policyShowAll'"
            :label="'Policy-Show-All'"
            :name="'Policy-Show-All'"
            :value="formValues['Policy-Show-All']"
            description="Optional: trigger the integration for all scan results. If set to true, integration will be triggered even for old scan results. Default value: false"
            :inputHandler="updateField"
          />
        </div>
      </form>
    </div>
  </div>
</template>

<script>
import { mapState } from "vuex";
import { UPDATE_ROUTE_ACTION, ADD_ROUTE_ACTION, REMOVE_ROUTE_ACTION } from "./../store/store";
import ValidationMixin from "./validator";
import FormFieldMixin from "./form";
import PluginProperty from "./PluginProperty.vue";
import PluginCheckboxProperty from "./PluginCheckboxProperty.vue";

export default {
  data() {
    return {
      fields: {},
      errors: {},
      name: "",
    };
  },
  mixins: [FormFieldMixin, ValidationMixin],
  components: {
    PluginProperty,
    PluginCheckboxProperty,
  },
  computed: {
    ...mapState({
      formValues(state) {
        //required for mixins
        const found = state.config.routes.filter(
          (item) => item.name === this.name
        );

        const result = found.length ? { ...found[0] } : {};

        if(!result.output) {
            result.output = []
        }

        return result;
      },
      availableOutputs(state) {
        return state.config.outputs.map((item) => item.name);
      },
    }),
  },
  methods: {
    doSubmit() {
      if (!this.isFormValid()) {
        return;
      }

      if (this.name) {
        this.$store.dispatch(UPDATE_ROUTE_ACTION, {
          value: this.formValues,
          name: this.name,
        });
      } else {
        this.$store.dispatch(ADD_ROUTE_ACTION, this.formValues);
      }
      this.$router.push({ name: "routes" });

    },
    doRemove() {
      this.$store.dispatch(REMOVE_ROUTE_ACTION, this.name);
      this.$router.push({ name: "routes" });
    },
    uniqueName(label, value) {
      if  (!value) {
        return `${label} is required`
      }
      const found = this.$store.state.config.routes.filter(
        (item) => item.name === value
      );

      if (found.length > 0 && found[0].name != this.name) {
        return `${value} is not unique`
      }
      return false
    }

  },
  mounted() {
    this.name = this.$route.params.name;
  },
};
</script>
