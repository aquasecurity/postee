export default {
    methods: {

        updateField(e) {
            const propName = e.target.attributes["name"].value;
            const inputType = e.target.attributes["type"]?.value;
            this.formValues[propName] =
                inputType == "checkbox" ? e.target.checked : e.target.value;
        },
        updateCollectionField(e) {
            const propName = e.target.attributes["name"].value;
            const v = e.target.value.split(",").map((s) => s.trim());

            this.formValues[propName] = v;
        },
        isFormValid() {
            let firstElement;
            this.errors = {}

            for (const id in this.fields) {
                const validator = this.fields[id];
                const validationFn = validator.validationFn;
                const element = document.getElementById(id);

                if (element) {
                    //only elements in DOM are validated
                    const r = validationFn(
                        validator.label,
                        this.formValues[validator.name]
                    );
                    if (r) {
                        this.errors[validator.name] = r;
                        if (firstElement === undefined) {
                            firstElement = element;
                        }
                    }
                }
            }

            firstElement && firstElement.focus();

            return Object.keys(this.errors).length === 0;
        }
    }
}