polarity.export = PolarityComponent.extend({
    details: Ember.computed.alias('block.data.details'),
    init() {
        this._super(...arguments);
        this.set('results', Ember.A([]));
    },
    observer: Ember.on('init', Ember.observer('block.data.details', function () {
        let results = this.get('block.data.details');
        this.set('results', results);
    })),
    actions: {
        toggle: function (key) {
            let results = this.get('results');
            results = JSON.parse(JSON.stringify(results));

            results.forEach(result => {
                if (result.__id === key) {
                    console.error('found item to toggle, now ' + !result.open);
                    result.open = !result.open;
                }
            });

            this.set('results', results);
            this.notifyPropertyChange('results');
        }
    }
});
