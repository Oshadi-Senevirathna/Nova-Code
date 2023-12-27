import { Grid, Switch, Typography } from '../../../node_modules/@mui/material/index';
import { useEffect, useState } from 'react';

export default function ToggleSetting(props) {
    const [checked, setChecked] = useState(false);

    useEffect(() => {
        setChecked(props.setting.data.value !== undefined ? props.setting.data.value : props.setting.data.defaultValue);
    }, [props.setting.data.value, props.setting.data.defaultValue]);

    return (
        <div style={{ paddingTop: '10px', paddingLeft: '20px' }}>
            <Grid container>
                <Grid item xs={10}>
                    <Typography style={{ textAlign: 'left', paddingBottom: '5px' }} variant="body1">
                        <b>{props.setting.displayName}</b>
                    </Typography>
                    <Typography style={{ textAlign: 'left' }} variant="body2">
                        {props.setting.description}
                    </Typography>
                </Grid>
                <Grid item xs={2}>
                    <Switch
                        id={`${props.setting.type}_${props.setting.name}_value`}
                        checked={checked !== undefined ? checked : false}
                        onClick={() => {
                            let newValue = !checked;
                            setChecked(newValue);
                            props.onValueChange(props.setting, newValue);
                        }}
                        name="settings-switch"
                        color="primary"
                    />
                </Grid>
            </Grid>
        </div>
    );
}
