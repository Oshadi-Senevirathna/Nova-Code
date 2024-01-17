class Setting {
    constructor(object) {
        this.instance_name = object['instance_name'];
        this.UUID = object['UUID'];
        this.module = object['module'];
        this.category = object['category'];
        this.value = object['value'];
    }
}

export default Setting;
