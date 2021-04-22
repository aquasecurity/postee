class validator {
    constructor(fields, validationFn) {
        this.validationFn = validationFn
        this.register = (id, label, name) => {
            this.label = label
            this.name = name
            fields[id] = this
        }
    }
}
export default validator
