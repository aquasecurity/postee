export default {
    methods: {

        updateField(e) {
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
            this.formValues[propName] = v;
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