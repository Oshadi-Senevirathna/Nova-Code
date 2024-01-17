import configs from './logs-config.json';
import { makeStyles } from '../../../node_modules/@mui/styles/index';
import { Typography } from '../../../node_modules/@mui/material/index';
import { ENTITY_NAME_LOGS_USER } from 'framework/caching/entity-cache';
import moment from '../../../node_modules/moment/moment';
import CustomDatatable from 'components/styledMUI/Datatable';

const useStyles = makeStyles((theme) => ({
    root: {
        width: '96%',
        marginTop: '2%',
        marginLeft: 'auto',
        marginRight: 'auto'
    },
    progressBar: {
        marginTop: '20px',
        marginBottom: '20px',
        marginRight: '20px'
    },
    button: { marginRight: '20px' },
    heading: {
        fontSize: 20,
        fontWeight: 'bold',
        paddingBottom: 15
    }
}));

const LogsPages = () => {
    const classes = useStyles();

    var configReshaped = configs;
    for (let i = 0; i < configReshaped.fields.length; i++) {
        if (configReshaped.fields[i].name === 'timestamp') {
            configReshaped.fields[i].options.customBodyRender = (value, tableMeta, updateValue) => {
                if (value) {
                    value = String(new Date(value));
                    value = moment(value).format('MMMM Do YYYY, h:mm:ss a');
                    return <>{value}</>;
                }
            };
        }
    }

    return (
        <div className={classes.root}>
            <Typography className={classes.heading}>{configReshaped.name}</Typography>
            <div style={{ marginRight: 20 }}>
                <CustomDatatable
                    entityName={ENTITY_NAME_LOGS_USER}
                    configs={configReshaped}
                    initSortField={'timestamp'}
                    initSortDirection={-1}
                />
            </div>
        </div>
    );
};

export default LogsPages;
