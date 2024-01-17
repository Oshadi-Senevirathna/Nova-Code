import { makeStyles } from '../../../node_modules/@mui/styles/index';
import { Divider, Grid, Typography } from '../../../node_modules/@mui/material/index';
import React from 'react';

const useStyles = makeStyles((theme) => ({
    root: {
        width: '100%',
        paddingRight: '20px'
    },
    paper: {
        width: '100%',
        marginBottom: 1,
        paddingLeft: '10px',
        paddingRight: '10px'
    }
}));

const Summary = ({ summary }) => {
    const classes = useStyles();
    return (
        <React.Fragment>
            <Grid container>{getSummaryEntries(summary)}</Grid>
        </React.Fragment>
    );
};

const getSummaryEntries = (summary) => {
    if (summary === undefined || summary === null || summary.length <= 0) {
        return <React.Fragment></React.Fragment>;
    }
    var len = summary.length;
    var count = 0;
    return summary.map((entry) => {
        count++;
        if (count === len) {
            return <SummaryEntry key={count} entry={entry} divider={false}></SummaryEntry>;
        } else {
            return <SummaryEntry key={count} entry={entry} divider={true}></SummaryEntry>;
        }
    });
};

const SummaryEntry = ({ entry, divider }) => {
    return (
        <React.Fragment>
            <Grid item xs={2}>
                <div style={{ padding: '5px', marginBottom: 0, display: 'inline-flex' }}>
                    <Typography style={{ margin: 0 }} variant="body2">
                        {entry.heading} :&nbsp; <b>{entry.value}</b>
                    </Typography>
                </div>
            </Grid>
            {divider && <Divider orientation="vertical" flexItem />}
        </React.Fragment>
    );
};

export default Summary;
