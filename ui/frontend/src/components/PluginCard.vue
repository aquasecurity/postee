<template>
    <div class="col mb-4">
        <div class="card text-center">
            <div class="card-header">
                Plugin name {{ title }} (Plugin type)
            </div>
            <div class="card-body">
                <h5 class="card-title">Was sent {{ sentCount }}</h5>
                <router-link :to="{name: 'plugin', params: {name: title}}" class="card-link">Edit</router-link>
            </div>
        </div>
    </div>
</template>

<script>
export default {
    props: ['title'],
    data() {
        return {
            sentCount: 10
        };
    }
}
</script>