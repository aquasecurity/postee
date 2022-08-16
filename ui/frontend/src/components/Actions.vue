<template>
<div >
    <div class="row justify-content-end pb-3 pr-3">
        <router-link :to="{name: 'add-action'}" class="btn btn-primary">Add Action</router-link>
    </div>
  <div class="card-header"><h3>Actions</h3></div>
  <div class="card-body">An Action is a enforceable step that enables the Postee operator to act upon incoming events.</div>
    <div class="row row-cols-1 row-cols-md-3">
        <ActionCard v-for="(action, index) in actions"
            :key="index"
            :type="action.type"
            :name="action.name"
            :enable="action.enable">
        </ActionCard>
    </div>
</div>
</template>
<script>
import ActionCard from './ActionCard.vue';
import { mapState} from 'vuex'

export default {
    components: {
        ActionCard
    },
    computed: {
        ...mapState({
            actions (state) {
                return state.actions.all
            }
        })
    }

}
</script>