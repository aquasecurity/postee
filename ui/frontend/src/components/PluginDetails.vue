<template>
    <div class="card mt-4">
<!--        <h1>Details for plugin {{ $route.params.name }}</h1> -->
        <div class="card-header">
            {{ plgType }}
        </div>
        <div class="card-body">
            <form>
                <div class="form-group form-check">
                    <input type="checkbox" class="form-check-input" id="plaginEnable">
                    <label class="form-check-label" for="plaginEnable">enable plugin</label>
                </div>
                <button type="submit" class="btn btn-primary">Submit</button>
            </form>
        </div>
    </div>
</template>
<script>
export default {
    data() {
        return {
            plgType: "Add new plugin"
        };
    },
    mounted() {
        if (this.$route.params.name != null) {
            this.plgType = this.$route.params.name;
        }
    }    
}
</script>