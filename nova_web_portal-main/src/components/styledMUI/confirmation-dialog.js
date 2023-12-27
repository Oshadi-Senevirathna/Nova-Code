import React, { useEffect } from 'react';
import { Button, Dialog, DialogActions, DialogContent, DialogContentText, DialogTitle } from '@mui/material';

export default function ConfirmationDialog(props) {
    const [open, setOpen] = React.useState(false);

    useEffect(() => {
        setOpen(props.open);
    }, [props.open]);

    const handleCancel = () => {
        setOpen(false);
        props.onCancel();
    };

    const handleOK = () => {
        setOpen(false);
        props.onOK();
    };

    return (
        <div>
            <Dialog
                open={open}
                fullWidth={true}
                onClose={handleCancel}
                aria-labelledby="alert-dialog-title"
                aria-describedby="alert-dialog-description"
            >
                <DialogTitle id="alert-dialog-title">
                    <b>{props.title}</b>
                </DialogTitle>
                <DialogContent>
                    <DialogContentText id="alert-dialog-description">{props.message}</DialogContentText>
                </DialogContent>
                <DialogActions>
                    <Button key={'conf-ok'} onClick={handleCancel} size="medium" variant="contained" color="primary">
                        Cancel
                    </Button>
                    <Button key={'conf-cancel'} onClick={handleOK} size="medium" variant="contained" color="primary">
                        OK
                    </Button>
                </DialogActions>
            </Dialog>
        </div>
    );
}
