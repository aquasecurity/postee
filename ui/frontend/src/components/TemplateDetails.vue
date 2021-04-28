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
            <label class="form-label" for="input">REGO template:</label>

            <!-- TODO add code mirror support -->
            <textarea
              :value="formValues.body"
              id="body"
              placeholder="add REGO template"
              name="body"
              @input="updateField"
              class="form-control"
              rows="3"
              v-bind:class="{ 'is-invalid': errors.input }"
            ></textarea>
            <small class="form-text text-muted">
              REGO template to render received events
            </small>
            <div class="form-text invalid-feedback">{{ errors.input }}</div>
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
    PluginProperty
  },
  computed: {
    ...mapState({
      formValues(state) {
        //required for mixins
        const found = state.templates.all.filter(
          (item) => item.name === this.name
        );

        const result = found.length ? { ...found[0] } : {};

        return result;
      }
    }),
  },
  methods: {
    doSubmit() {
      if (!this.isFormValid()) {
        return;
      }

      if (this.name) {
        this.$store.dispatch("templates/update", {
          value: this.formValues,
          name: this.name,
        });
      } else {
        this.$store.dispatch("templates/add", this.formValues);
      }
      this.$router.push({ name: "templates" });

    },
    doRemove() {
      this.$store.dispatch("templates/remove", this.name);
      this.$router.push({ name: "templates" });
    },
    uniqueName(label, value) {
      if  (!value) {
        return `${label} is required`
      }
      const found = this.$store.state.templates.all.filter(
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
